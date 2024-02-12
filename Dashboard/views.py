from django.shortcuts import render,redirect
from users.models import User,Product,Category
from django.core.files.storage import FileSystemStorage
from django.utils.datastructures import MultiValueDictKeyError
from django.contrib import messages



# Create your views here.


def index(request):
    user_count = User.objects.count()
    return render(request,"index.html",{'user_count':user_count})

def Register(request):
    return render(request,"Register.html")

def createuser(request):
    return render(request,"CreateUser.html")

def saveuser(request):
    if request.method == "POST":
        un = request.POST.get('name')
        em = request.POST.get('email')
        pwd = request.POST.get('pwd1')
        cnpwd = request.POST.get('pwd2')
        obj = User(name=un,email=em,password=pwd,password2=cnpwd)
        obj.save()
    return redirect(viewuser)

def viewuser(request):
    lo = User.objects.all()
    return render(request,"ViewUser.html",{'lo':lo})

def deleteuser(request,dlt):
    delt = User.objects.filter(id=dlt)
    delt.delete()
    return redirect(viewuser)

def viewproduct(request):
    pro = Product.objects.all()
    return render(request,"ViewProduct.html",{'pro':pro})


def addcategory(request):
    cat = Category.objects.all()
    return render(request,"AddCategory.html",{'cat':cat})


def addproduct(request):
    categ = Category.objects.all()
    return render(request,"AddProducts.html",{'categ':categ})

def saveproduct(request):
    if request.method == "POST":
        pn = request.POST.get('pname')
        pd = request.POST.get('pdes')
        pi = request.FILES['pimage']
        pc = request.POST.get('pcat')
        pp = request.POST.get('pprice')
        ps = request.POST.get('psize')
        obj = Product(Product_Name=pn,Description=pd,Product_Image=pi,Product_Category=pc,Price=pp,Size=ps)
        obj.save()
        return redirect(addproduct)

def editproduct(request,dataid):
    prod = Category.objects.all()
    ed = Product.objects.get(id=dataid)
    return render(request,"EditProduct.html",{'ed':ed,'prod':prod})

def updateproduct(request,dataid):
    if request.method == "POST":
        p_name = request.POST.get('pname')
        p_des = request.POST.get('pdes')
        try:
            img = request.FILES['pimage']
            fs = FileSystemStorage()
            file = fs.save(img.name,img)
        except MultiValueDictKeyError:
            file = Product.objects.get(id=dataid).Product_Image
        p_cat = request.POST.get('pcat')
        p_price = request.POST.get('pprice')
        p_size = request.POST.get('psize')
        Product.objects.filter(id=dataid).update(Product_Name=p_name,Description=p_des,Product_Image=file,Product_Category=p_cat,Price=p_price,Size=p_size)
    return redirect(viewproduct)

def deleteproduct(request,delpro):
    delete = Product.objects.filter(id=delpro)
    delete.delete()
    return redirect(viewproduct)