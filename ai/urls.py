from django.urls import path
from .views import FAQView,GenerateEmailResponseView

urlpatterns = [
    path('faq/', FAQView.as_view(), name='faq'),
    path('faq/<int:id>/', FAQView.as_view(), name='faq_detail'),
    # path('pinecone-data/', PineconeDataView.as_view(), name='pinecone_data'), 
    path('ai-response/', GenerateEmailResponseView.as_view(), name='retrieve_faqs'),
]
