from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from django.db.models import Q
from rest_framework.permissions import IsAuthenticated
from pinecone import Pinecone, ServerlessSpec
from openai import OpenAI
from .models import FAQ
from .serializers import FAQSerializer
from ZenflowAi import utils, constants
from django.conf import settings
import re


# Initialize Pinecone
pinecone_env = settings.PINECONE_ENV
pc = Pinecone(api_key=settings.PINECONE_API_KEY)
# print(pc.list_indexes().names())

# making index 
index = "clientfaq"
if index not in [index.name for index in pc.list_indexes()]:
    pc.create_index(
        name=index,
        dimension=1536,
        metric="cosine",
        spec=ServerlessSpec(cloud="aws", region=pinecone_env),
    )
index = pc.Index(index)
# if index:
#     print(f"Index '{index}' created successfully.")
# else:
#     print(f"Index '{index.name}' already exists.")
client = OpenAI(api_key=settings.OPENAI_API_KEY)
# print(client, "lll")


class FAQView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = FAQSerializer(data=request.data)
        if serializer.is_valid():
            faq_instance = serializer.save(user=request.user)
            faq_text = faq_instance.question
            embedding = self.get_embedding(faq_text)
            index.upsert(
                [
                    {
                        "id": str(faq_instance.id),
                        "values": embedding,
                        "metadata": {
                            "client_id": request.user.id,
                            "question": faq_instance.question,
                            "answer": faq_instance.answer,
                        },
                    }
                ]
            )
            return utils.success_response(
                constants.MESSAGES["FAQ_UPLOADED"],
                serializer.data,
                status.HTTP_201_CREATED,
            )
        return utils.error_response(
            constants.MESSAGES["FAQ_REQUIRED"],
            serializer.errors,
            status.HTTP_400_BAD_REQUEST,
        )
    def get(self, request, id=None):
        user = request.user
        if id:
            try:
                faq = FAQ.objects.get(pk=id, is_deleted=False, user=user)
                serializer = FAQSerializer(faq)
                return utils.success_response(
                    constants.MESSAGES["FAQ_RETRIEVED"],
                    serializer.data,
                    status.HTTP_200_OK,
                )
            except FAQ.DoesNotExist:
                return utils.error_response(
                    constants.MESSAGES["FAQ_NOT_FOUND"],
                    status_code=status.HTTP_404_NOT_FOUND,
                )

        search_query = request.query_params.get("search", None)
        faqs = (
            FAQ.objects.filter(
                Q(question__icontains=search_query) | Q(answer__icontains=search_query),
                is_deleted=False,
                user=user,
            )
            if search_query
            else FAQ.objects.filter(is_deleted=False, user=user)
        )
        paginator = PageNumberPagination()
        result_page = paginator.paginate_queryset(faqs, request)
        serializer = FAQSerializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def put(self, request, id):
        try:
            faq = FAQ.objects.get(pk=id, is_deleted=False)
            serializer = FAQSerializer(faq, data=request.data, partial=True)
            if serializer.is_valid():
                updated_faq = serializer.save()
                new_text = updated_faq.question + " " + updated_faq.answer
                new_embedding = self.get_embedding(new_text)
                index.upsert(
                    [
                        {
                            "id": str(updated_faq.id),
                            "values": new_embedding,
                            "metadata": {
                                "user_id": request.user.id,
                                "question": updated_faq.question,
                                "answer": updated_faq.answer,
                            },
                        }
                    ]
                )
                return utils.success_response(
                    constants.MESSAGES["FAQ_UPDATED"],
                    serializer.data,
                    status.HTTP_200_OK,
                )
            return utils.error_response(
                constants.MESSAGES["FAQ_REQUIRED"],
                serializer.errors,
                status.HTTP_400_BAD_REQUEST,
            )
        except FAQ.DoesNotExist:
            return utils.error_response(
                constants.MESSAGES["FAQ_NOT_FOUND"],
                status_code=status.HTTP_404_NOT_FOUND,
            )

    def delete(self, request, id):
        try:
            faq = FAQ.objects.get(pk=id)
            faq.is_deleted = True
            faq.save()
            # deletedFAQ = index.fetch(ids=[str(265)])
            # print(deletedFAQ, "deletedFAQ")
            index.delete(ids=[str(id)])
            return utils.success_response(
                constants.MESSAGES["FAQ_DELETED"], status.HTTP_200_OK
            )
        except FAQ.DoesNotExist:
            return utils.error_response(
                constants.MESSAGES["FAQ_NOT_FOUND"],
                status_code=status.HTTP_404_NOT_FOUND,
            )
    # @classmethod
    def get_embedding(self, text):
        response = client.embeddings.create(input=text, model="text-embedding-3-small")
        print("FAQ created in Pinecone sucessfully")
        return response.data[0].embedding
    # @classmethod
    def retrieve_relevant_faqs(self, query, client_id, top_k=3):
        query_embedding = self.get_embedding(query)
        results = index.query(
            vector=query_embedding,
            filter={"client_id": client_id},
            top_k=top_k,
            include_metadata=True,
        )
        faqs = [
            {
                "question": match["metadata"]["question"],
                "answer": match["metadata"]["answer"],
            }
            for match in results["matches"]
        ]
        return faqs

import json
class GenerateEmailResponseView(APIView):
    """API endpoint to generate AI-powered email responses based on FAQs."""
    
    @classmethod
    def get_embedding(self, text):
        """Generate an embedding for the given text using OpenAI."""
        response = client.embeddings.create(input=text, model="text-embedding-3-small")
        return response.data[0].embedding
    
    @classmethod
    def retrieve_relevant_faqs(self, query, clientID, top_k=3):
        query_embedding = self.get_embedding(query)
        results = index.query(
            vector=query_embedding,
            filter={"client_id": clientID},
            top_k=top_k,
            include_metadata=True,
        )
        faqs = [
            {
                "question": match["metadata"]["question"],
                "answer": match["metadata"]["answer"],
            }
            for match in results["matches"]
        ]
        # print("Retrieved FAQs:", faqs)
        return faqs
    
    def post(self, request):
        user_query = request.data.get("user_query")
        clientID = request.data.get("clientID", "Our Support Team")

        if not user_query:
            return Response(
                {"error": "User query is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        faqs = self.retrieve_relevant_faqs(user_query, clientID)
        # print(f"Retrieved FAQs: {faqs}")
        print("user_query", user_query)
        # If no relevant FAQs are found, return a predefined message
        if not faqs:
            return Response(
                {
                    "response": "Dear customer, we couldn't find an exact answer for your query. Could you please provide more details so we can assist you better?"
                },
                status=status.HTTP_200_OK,
            )

        faqs_text = "\n\n".join(
            f"Q: {faq['question']}\nA: {faq['answer']}" for faq in faqs
        )

        prompt = f"""
        You are an AI support assistant for {clientID}. A customer has asked:
        "{user_query}"

        Here are relevant FAQs for this client:
        {faqs_text}  

        ### **Instructions:**
        - **Detect the language of the customer's query.**  
        - **Respond in the same language** as the customer's question (English, Spanish, etc.).  
        - Generate a **professional, friendly, and informative response** using the FAQ knowledge.  
        - If no relevant FAQ fully answers the question, politely ask for more details in the same language.

        ---

        ### **Response Guidelines:**  
        - Start with a **polite greeting** in the detected language.  
        - Acknowledge the customer's query respectfully.  
        - Provide the **entire FAQ answer without truncation, only rephrasing for clarity**.  
        - Maintain a **professional yet warm and supportive tone**.  
        - If necessary, suggest **next steps** or invite further questions.  
        - End with a **professional closing in the detected language**.
        - Ensure the response is a **fully structured JSON object**
        - Detect this language "{user_query}" and send response in this language.

        ---

        ## **Response Formats:**  

        ### **If a relevant FAQ is found:**  


        ```json
        {{
            "status": "success",
            "message": "Dear Customer,\n\nThank you for reaching out with your question. I’m happy to assist you!\n\n[Provide a friendly and concise answer based on the FAQ, emphasizing clarity and reassurance.]\n\nIf you need further details or have any additional questions, feel free to ask. We’re here to help!\n\nBest regards,\nZenflow AI",
            "code": "FAQ_FOUND",
            "suggestion": "Feel free to ask any follow-up questions or explore other resources."
        }}
        If no relevant FAQ is found, genrate response in below json format

        {{
            "status": "error",
            "message": "We could not find a relevant answer in our FAQs for your query. Could you please provide more details so we can assist you better?",
            "code": "FAQ_NOT_FOUND",
            "suggestion": "Please provide more information or contact our support team directly for assistance."
        }}
        Now, generate the response.
        """
        try:
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                temperature=0.2,
                max_tokens=2000,
                messages=[{"role": "system", "content": prompt}],
            )   
            ai_response = response.choices[0].message.content
            cleaned_response = re.sub(r"```json|```", "", ai_response).strip()
            ai_response_dict = json.loads(cleaned_response) 
            message = ai_response_dict.get("message", "Default message if not found")

            return Response({"response": message}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
