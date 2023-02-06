from django.shortcuts import render
from store.models import Product


def home(req):
    products = Product.objects.all().filter(is_available=True)
    context = {
        'products': products
    }
    return render(req, 'home.html', context)
