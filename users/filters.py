import django_filters
from .models import Product

class ProductFilter(django_filters.FilterSet):
    search = django_filters.CharFilter(field_name='Product_Name', lookup_expr='icontains', label='Search by Product Name')
    category = django_filters.CharFilter(field_name='Product_Category__Category_Name', lookup_expr='icontains', label='Filter by Category')
    min_price = django_filters.NumberFilter(field_name='Price', lookup_expr='gte', label='Min Price')
    max_price = django_filters.NumberFilter(field_name='Price', lookup_expr='lte', label='Max Price')
    color = django_filters.ChoiceFilter(field_name='Color', choices=Product.COLOR_CHOICES, label='Color')
    size = django_filters.ChoiceFilter(field_name='Size', choices=Product.SIZE_CHOICES, label='Size')

    class Meta:
        model = Product
        fields = ['search', 'category', 'min_price', 'max_price', 'color', 'size']