from django.shortcuts import render, redirect, HttpResponse
from django.contrib import messages, auth
from django.contrib.auth.decorators import login_required

# verification email
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage

from .models import Account
from .forms import RegistrationForm
# Create your views here.


def register(req):
    if req.method == 'POST':
        form = RegistrationForm(req.POST)
        if form.is_valid():
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            email = form.cleaned_data['email']
            phone_number = form.cleaned_data['phone_number']
            password = form.cleaned_data['password']

            username = email.split('@')[0]

            user = Account.objects.create_user(
                first_name=first_name, last_name=last_name, email=email, username=username, password=password)
            user.phone_number = phone_number
            user.save()

            # USER ACTIVATION
            current_site = get_current_site(req)
            mail_subject = 'Please activate your account'
            message = render_to_string('accounts/account_verification_email.html', {
                'user': user,
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()

            # messages.success(
            #      req, 'We have sent you a verification email to confirm your account')
            return redirect('/accounts/login/?command=verification&email='+email)

    else:
        form = RegistrationForm()
    context = {
        'form': form
    }
    return render(req, 'accounts/register.html', context)


def login(req):
    if req.method == "POST":
        email = req.POST['email']
        password = req.POST['password']

        user = auth.authenticate(email=email, password=password)

        if user is not None:
            auth.login(req, user)
            return redirect('dashboard')
        else:
            messages.error(req, 'Invalid Credentials')
            return redirect('login')
    return render(req, 'accounts/login.html')


@login_required(login_url='login')
def logout(req):
    auth.logout(req)
    messages.success(req, 'You are logged out')
    return redirect('login')


def activate(req, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except (TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(req, 'Your account activated successfully')
        return redirect('login')
    else:
        messages.error(req, 'Invalid activation link')
        return redirect('register')


@login_required(login_url='login')
def dashboard(req):
    return render(req, 'accounts/dashboard.html')


def forgotPassword(req):
    if req.method == 'POST':
        email = req.POST['email']
        if Account.objects.filter(email=email).exists():
            user = Account.objects.get(email__exact=email)

            # RESET PASSWORD MAIL
            current_site = get_current_site(req)
            mail_subject = 'Reset your password'
            message = render_to_string('accounts/reset_password_email.html', {
                'user': user,
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()

            messages.success(
                req, 'Password Reset email has been sent to your email address')
            return redirect('login')
        else:
            messages.error(req, 'Account does not exist')
            return redirect('forgotPassword')
    return render(req, 'accounts/forgotPassword.html')


def resetpassword_validate(req, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except (TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        req.session['uid'] = uid
        messages.success(req, 'Please reset your password')
        return redirect('resetPassword')
    else:
        messages.error(req, 'This link has been expired')
        return redirect('login')


def resetPassword(req):
    if req.method == 'POST':
        password = req.POST['password']
        confirm_password = req.POST['confirm_password']

        if password == confirm_password:
            uid = req.session.get('uid')
            user = Account.objects.get(pk=uid)
            user.set_password(password)
            user.save()
            messages.success(req, 'Password reset Successful')
            return redirect('login')
        else:
            messages.error(req, 'Password don\'t match')
            return redirect('resetPassword')
    else:
        return render(req, 'accounts/resetPassword.html')
