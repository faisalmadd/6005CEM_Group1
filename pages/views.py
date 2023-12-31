import base64
import binascii
from django.contrib.auth import login, authenticate
from django.contrib import auth
from django.contrib.auth.forms import UserChangeForm
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.messages.views import SuccessMessageMixin
from django.db import transaction
from django.db.models import Count, Avg, QuerySet
from django.forms import inlineformset_factory
from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404, HttpResponse
from django.contrib import messages
from django.urls import reverse_lazy, reverse
from django.views.generic import CreateView, ListView, DeleteView, UpdateView, DetailView
from .models import TakenQuiz, Profile, Quiz, Question, Answer, Student, User, Course, Tutorial, Notes, Comments, AuditLog
from .forms import StudentRegistrationForm, LecturerRegistrationForm, AdminStudentRegistrationForm, QuestionForm, \
    BaseAnswerInlineFormSet, CommentForm, AddCourseForm
from utils.crypto_utils import encrypt_data, decrypt_data
from django_ratelimit.decorators import ratelimit
from django.contrib.auth.decorators import login_required, user_passes_test
import pyotp
from datetime import datetime, timedelta
from django.core.mail import send_mail
from django.conf import settings
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseBadRequest
from django.core.exceptions import ValidationError
from django.core.validators import FileExtensionValidator
from django.utils.html import escape
from pyclamd import ClamdAgnostic

# Encryption/Decryption AES Key & Initialization Vector
key = b'\x16sI\x8f9\x05\x12kKdf\x90\xe55\xa2\xbcrd\x94Z\tP?\xa5\xe2l\xa9\x11\xc6&\xab\x1b'
iv = b'Q\x85\xfe`@\xcd\xbc\xf2\x99\x13\x05qy)\x81X'


# Create your views here.
@ratelimit(key='ip', rate='5/m', block=True)
def homepage_view(request, *args, **kwargs):
    return render(request, "home.html", {})


def is_admin(user):
    return user.is_authenticated and (user.is_admin or user.is_superuser)

def is_lecturer(user):
    return user.is_authenticated and (user.is_lecturer or user.is_admin or user.is_superuser)

class StudentRegisterView(CreateView):
    model = User
    form_class = StudentRegistrationForm
    template_name = 'register.html'

    def get_context_data(self, **kwargs):
        kwargs['user_type'] = 'student'
        return super().get_context_data(**kwargs)

    def form_valid(self, form):
        # Encrypt email using the key and initialization vector
        encrypted_email = encrypt_data(form.cleaned_data['email'], key, iv)  # Encrypted email in bytes
        print('Original Data:', form.cleaned_data['email'])  # Raw data from user input
        print('Encrypted Data:', encrypted_email)  # Encrypted data in bytes

        # Save the encrypted email and other form data
        user = form.save()
        user.email = base64.b64encode(encrypted_email).decode('utf-8')  # Encode base64 to store as string in database
        print('Encoded Data:', user.email)  # Encoded data to be stored in database
        user.save()

        log = AuditLog(user='', datetime=datetime.now(), desc='Student account created')
        log.save()

        messages.success(self.request, f'Hi {user.username}, your account was created successfully!')
        return redirect('home')


@method_decorator(user_passes_test(is_admin, login_url='login_form'), name='dispatch')
class LecturerRegisterView(CreateView):
    model = User
    form_class = LecturerRegistrationForm
    template_name = 'dashboard/admin/add_lecturer.html'

    def get_context_data(self, **kwargs):
        kwargs['user_type'] = 'lecturer'
        return super().get_context_data(**kwargs)

    def form_valid(self, form):
        # Encrypt email using the key and initialization vector
        encrypted_email = encrypt_data(form.cleaned_data['email'], key, iv)
        print(encrypted_email)

        # Save the encrypted email and other form data
        user = form.save()
        user.email = base64.b64encode(encrypted_email).decode('utf-8')  # Encode base64 to store as string in database
        print(user.email)
        user.save()

        decrypted_data = decrypt_data(encrypted_email, key, iv)
        print("Decrypted Data:", decrypted_data)

        log = AuditLog(user=self.request.user.id, datetime=datetime.now(), desc='Admin create lecturer account')
        log.save()

        messages.success(self.request, f'{user.username} account was created successfully!')

        return redirect('admin_dashboard')


@method_decorator(user_passes_test(is_admin, login_url='login_form'), name='dispatch')
class AdminStudentRegisterView(CreateView):
    model = User
    form_class = AdminStudentRegistrationForm
    template_name = 'dashboard/admin/add_student.html'

    def get_context_data(self, **kwargs):
        kwargs['user_type'] = 'student'
        return super().get_context_data(**kwargs)

    def form_valid(self, form):
        # Encrypt email using the key and initialization vector
        encrypted_email = encrypt_data(form.cleaned_data['email'], key, iv)
        print(encrypted_email)

        # Save the encrypted email and other form data
        user = form.save()
        user.email = base64.b64encode(encrypted_email).decode('utf-8')  # Encode base64 to store as string in database
        print(user.email)
        user.save()

        decrypted_data = decrypt_data(encrypted_email, key, iv)
        print("Decrypted Data:", decrypted_data)

        log = AuditLog(user=self.request.user.id, datetime=datetime.now(), desc='Admin create student account')
        log.save()

        messages.success(self.request, f'{user.username} account was created successfully!')

        return redirect('admin_dashboard')


@ratelimit(key='ip', rate='5/m', block=True)
def login_form(request):
    return render(request, 'login.html')


@ratelimit(key='ip', rate='5/m', block=True)
def contact_view(request):
    return render(request, 'contact.html')


@ratelimit(key='ip', rate='5/m', block=True)
def login_view(request, *args, **kwargs):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        sanitized_username = escape(username)
        user = authenticate(request, username=sanitized_username, password=password)
        if user is not None and user.is_active:
            auth.login(request, user)

            # uncomment below code for MFA OTP

            # if user.is_admin or user.is_superuser:
            #     request.session['where_to'] = "admin_dashboard"
            # elif user.is_lecturer:
            #     request.session['where_to'] = "lecturer_dashboard"
            # elif user.is_student:
            #     request.session['where_to'] = "student_dashboard"
            # else:
            #     request.session['where_to'] = "login_form"

            # request.session['name'] = username
            # send_otp(request)
            # return redirect('otp')

            if user.is_admin or user.is_superuser:
                log = AuditLog(user=request.user.id, datetime=datetime.now(), desc='Admin login')
                log.save()
                return redirect('admin_dashboard')
            elif user.is_lecturer:
                log = AuditLog(user=request.user.id, datetime=datetime.now(), desc='Lecturer login')
                log.save()
                return redirect('lecturer_dashboard')
            elif user.is_student:
                log = AuditLog(user=request.user.id, datetime=datetime.now(), desc='Student login')
                log.save()
                return redirect('student_dashboard')
            else:
                return redirect('login_form')
        else:
            log = AuditLog(user='', datetime=datetime.now(), desc='Invalid login')
            log.save()
            messages.info(request, "Invalid Username or Password")
            return redirect('login_form')


def otp_view(request):
    error_message = None
    print(f"Error: {error_message}")
    if request.method == 'POST':
        otp = request.POST['otp']
        where_to = request.session['where_to']

        otp_secret_key = request.session['otp_secret_key']
        otp_valid_date = request.session['otp_valid_date']

        print(f"input otp: {otp}")
        print(f"where to: {where_to}")
        print(f"secret key: {otp_secret_key}")

        if otp_secret_key and otp_valid_date is not None:
            valid_date = datetime.fromisoformat(otp_valid_date)
            if valid_date > datetime.now():
                print(f"got date verified")
                totp = pyotp.TOTP(otp_secret_key, interval=60)
                if totp.verify(otp):

                    del request.session['otp_secret_key']
                    del request.session['otp_valid_date']

                    print(f"got verified")
                    return redirect(where_to)

                    if where_to == "admin_dashboard":
                        print(f"got into admin dashboard if else")
                        log = AuditLog(user=request.user.id, datetime=datetime.now(), desc='Admin login')
                        log.save()
                        return redirect('admin_dashboard')
                    elif where_to == "lecturer_dashboard":
                        log = AuditLog(user=request.user.id, datetime=datetime.now(), desc='Lecturer login')
                        log.save()
                        return redirect('lecturer_dashboard')
                    elif where_to == "student_dashboard":
                        log = AuditLog(user=request.user.id, datetime=datetime.now(), desc='Student login')
                        log.save()
                        return redirect('student_dashboard')
                    else:
                        return redirect('login_form')
                else:
                    error_message = 'Invalid One-time Password'
            else:
                error_message = 'One-time Password has expired'
        else:
            error_message = 'Something went wrong. Please try loggin in again'


    return render(request, 'otp.html', {'error_message': error_message})


def send_otp(request):
    base32_key = pyotp.random_base32()
    totp = pyotp.TOTP(base32_key, interval=60)
    otp = totp.now()
    request.session['otp_secret_key'] = totp.secret
    valid_date = datetime.now() + timedelta(minutes=1)
    request.session['otp_valid_date'] = str(valid_date)

    print(f"Your one time password: {otp}")

    current_user = request.user
    user_id = current_user.id
    current_email = current_user.email
    current_name = current_user.username
    print(f"This is current users: {current_user}")
    print(f"This is users id: {user_id}")
    print(f"This is users email: {current_email}")
    print(f"This is user name: {current_name}")

    message = "Your one time password: " + otp
    email =  current_email
    name = current_name

    print(f"This is message: {message}")
    print(f"This is email: {email}")
    print(f"This is name: {name}")

    if email is not None:
        send_mail(
            "One Time Password for " + name, # email title
            message, # email content
            settings.EMAIL_HOST_USER, #sender email
            [email], # receiver email
            fail_silently=False)
    else:
        print("Make sure the user has an email")


@ratelimit(key='ip', rate='5/m', block=True)
@login_required(login_url='login_form')
@user_passes_test(is_lecturer, login_url='login_form')
def lecturer_create_profile(request):
    if request.method == 'POST':
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        email = request.POST['email']
        dob = request.POST['dob']
        bio = request.POST['bio']
        contact = request.POST['contact']
        profile_pic = request.FILES['profile_pic']
        current_user = request.user
        user_id = current_user.id
        print(user_id)

        # Encrypt fields using the key and initialization vector
        encrypted_first_name = encrypt_data(first_name, key, iv)
        encrypted_last_name = encrypt_data(last_name, key, iv)
        encrypted_dob = encrypt_data(dob, key, iv)
        encrypted_bio = encrypt_data(bio, key, iv)
        encrypted_contact = encrypt_data(contact, key, iv)
        encrypted_email = encrypt_data(email, key, iv)
        print(encrypted_email)

        encoded_first_name = base64.b64encode(encrypted_first_name).decode('utf-8')
        encoded_last_name = base64.b64encode(encrypted_last_name).decode('utf-8')
        encoded_dob = base64.b64encode(encrypted_dob).decode('utf-8')
        encoded_bio = base64.b64encode(encrypted_bio).decode('utf-8')
        encoded_contact = base64.b64encode(encrypted_contact).decode('utf-8')
        encoded_email = base64.b64encode(encrypted_email).decode('utf-8')
        print(encoded_email)

        Profile.objects.filter(id=user_id).create(user_id=user_id, contact=encoded_contact,
                                                  first_name=encoded_first_name, email=encoded_email,
                                                  last_name=encoded_last_name, bio=encoded_bio, dob=encoded_dob,
                                                  profile_pic=profile_pic)
        log = AuditLog(user=user_id, datetime=datetime.now(), desc='Lecturer profile created')
        log.save()
        messages.success(request, 'Your Profile Was Created Successfully')
        return redirect('lecturer_profile')
    else:
        current_user = request.user
        user_id = current_user.id
        users = Profile.objects.filter(user_id=user_id)
        users = {'users': users}
        return render(request, 'dashboard/lecturer/create_profile.html', users)


@ratelimit(key='ip', rate='5/m', block=True)
@login_required(login_url='login_form')
@user_passes_test(is_lecturer, login_url='login_form')
def lecturer_user_profile(request):
    current_user = request.user
    user_id = current_user.id
    users = Profile.objects.filter(user_id=user_id)
    print(users)

    if not users:
        # Handle the case where no users are found
        context = {'users': users}
        return render(request, 'dashboard/lecturer/view_profile.html', context)
    else:
        try:
            # Access the first user in the queryset
            user = users[0]
            # Decrypt necessary fields
            decrypted_email = decrypt_data(base64.b64decode(current_user.email), key, iv)
            decrypted_first_name = decrypt_data(base64.b64decode(user.first_name), key, iv)
            decrypted_last_name = decrypt_data(base64.b64decode(user.last_name), key, iv)
            decrypted_dob = decrypt_data(base64.b64decode(user.dob), key, iv)
            decrypted_bio = decrypt_data(base64.b64decode(user.bio), key, iv)
            decrypted_contact = decrypt_data(base64.b64decode(user.contact), key, iv)

            # Construct user_data dictionary
            user_data = {
                'username': current_user.username,
                'user_id': user.user_id,
                'email': decrypted_email,
                'first_name': decrypted_first_name,
                'last_name': decrypted_last_name,
                'dob': decrypted_dob,
                'bio': decrypted_bio,
                'contact': decrypted_contact,
                'profile_pic': user.profile_pic,
            }
            print(user_data)

            context = {'users': user_data}
            print(context)
            return render(request, 'dashboard/lecturer/view_profile.html', context)

        except binascii.Error as e:
            # Handle invalid base64-encoded strings
            print(f"Error decoding email for user {user_id}: {e}")


@ratelimit(key='ip', rate='5/m', block=True)
@login_required(login_url='login_form')
def student_create_profile(request):
    if request.method == 'POST':
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        email = request.POST['email']
        dob = request.POST['dob']
        bio = request.POST['bio']
        contact = request.POST['contact']
        profile_pic = request.FILES['profile_pic']
        current_user = request.user
        user_id = current_user.id
        print(user_id)

        # Encrypt fields using the key and initialization vector
        encrypted_first_name = encrypt_data(first_name, key, iv)
        encrypted_last_name = encrypt_data(last_name, key, iv)
        encrypted_dob = encrypt_data(dob, key, iv)
        encrypted_bio = encrypt_data(bio, key, iv)
        encrypted_contact = encrypt_data(contact, key, iv)
        encrypted_email = encrypt_data(email, key, iv)
        print(encrypted_email)

        encoded_first_name = base64.b64encode(encrypted_first_name).decode('utf-8')
        encoded_last_name = base64.b64encode(encrypted_last_name).decode('utf-8')
        encoded_dob = base64.b64encode(encrypted_dob).decode('utf-8')
        encoded_bio = base64.b64encode(encrypted_bio).decode('utf-8')
        encoded_contact = base64.b64encode(encrypted_contact).decode('utf-8')
        encoded_email = base64.b64encode(encrypted_email).decode('utf-8')
        print(encoded_email)

        Profile.objects.filter(id=user_id).create(user_id=user_id, contact=encoded_contact,
                                                  first_name=encoded_first_name, email=encoded_email,
                                                  last_name=encoded_last_name, bio=encoded_bio, dob=encoded_dob,
                                                  profile_pic=profile_pic)
        log = AuditLog(user=user_id, datetime=datetime.now(), desc='Student profile created')
        log.save()
        messages.success(request, 'Your Profile Was Created Successfully')
        return redirect('student_profile')
    else:
        current_user = request.user
        user_id = current_user.id
        users = Profile.objects.filter(user_id=user_id)
        users = {'users': users}
        return render(request, 'dashboard/student/create_profile.html', users)


@ratelimit(key='ip', rate='5/m', block=True)
@login_required(login_url='login_form')
def student_user_profile(request):
    current_user = request.user
    user_id = current_user.id
    users = Profile.objects.filter(user_id=user_id)
    print(users)

    if not users:
        # Handle the case where no users are found
        context = {'users': users}
        return render(request, 'dashboard/student/view_profile.html', context)
    else:
        try:
            # Access the first user in the queryset
            user = users[0]
            # Decrypt necessary fields
            decrypted_email = decrypt_data(base64.b64decode(current_user.email), key, iv)
            decrypted_first_name = decrypt_data(base64.b64decode(user.first_name), key, iv)
            decrypted_last_name = decrypt_data(base64.b64decode(user.last_name), key, iv)
            decrypted_dob = decrypt_data(base64.b64decode(user.dob), key, iv)
            decrypted_bio = decrypt_data(base64.b64decode(user.bio), key, iv)
            decrypted_contact = decrypt_data(base64.b64decode(user.contact), key, iv)

            # Construct user_data dictionary
            user_data = {
                'username': current_user.username,
                'user_id': user.user_id,
                'email': decrypted_email,
                'first_name': decrypted_first_name,
                'last_name': decrypted_last_name,
                'dob': decrypted_dob,
                'bio': decrypted_bio,
                'contact': decrypted_contact,
                'profile_pic': user.profile_pic,
            }
            print(user_data)

            context = {'users': user_data}
            print(context)
            return render(request, 'dashboard/student/view_profile.html', context)

        except binascii.Error as e:
            # Handle invalid base64-encoded strings
            print(f"Error decoding email for user {user_id}: {e}")


@ratelimit(key='ip', rate='5/m', block=True)
@login_required(login_url='login_form')
def student_dashboard(request, *args, **kwargs):
    student = User.objects.filter(is_student=True).count()
    lecturer = User.objects.filter(is_lecturer=True).count()
    course = Course.objects.all().count()
    users = User.objects.all().count()
    context = {'student': student, 'course': course, 'lecturer': lecturer, 'users': users}

    return render(request, "dashboard/student/dashboard.html", context)


@ratelimit(key='ip', rate='5/m', block=True)
@login_required(login_url='login_form')
@user_passes_test(is_lecturer, login_url='login_form')
def lecturer_dashboard(request, *args, **kwargs):
    student = User.objects.filter(is_student=True).count()
    lecturer = User.objects.filter(is_lecturer=True).count()
    course = Course.objects.all().count()
    users = User.objects.all().count()
    context = {'student': student, 'course': course, 'lecturer': lecturer, 'users': users}

    return render(request, "dashboard/lecturer/dashboard.html", context)


@ratelimit(key='ip', rate='5/m', block=True)
@login_required(login_url='login_form')
@user_passes_test(is_admin, login_url='login_form')
def admin_dashboard(request, *args, **kwargs):
    student = User.objects.filter(is_student=True).count()
    lecturer = User.objects.filter(is_lecturer=True).count()
    course = Course.objects.all().count()
    users = User.objects.all().count()
    context = {'student': student, 'course': course, 'lecturer': lecturer, 'users': users}

    return render(request, "dashboard/admin/dashboard.html", context)


@ratelimit(key='ip', rate='5/m', block=True)
@login_required(login_url='login_form')
@user_passes_test(is_lecturer, login_url='login_form')
def add_course(request):
    if request.method == 'POST':
        form = AddCourseForm(request.POST)
        if form.is_valid():
            name = form.cleaned_data['name']
            Course.objects.create(name=name)
            a = Course(name=name)
            a.save()
            log = AuditLog(user=request.user.id, datetime=datetime.now(), desc='Course created')
            log.save()
            messages.success(request, 'Successfully Added Course')
            return redirect('add_course')
        else:
            return HttpResponseBadRequest("No symbols allowed in course name")
    else:
        form = AddCourseForm()

        return render(request, 'dashboard/lecturer/add_course.html', {'form': form})


@method_decorator(user_passes_test(is_admin, login_url='login_form'), name='dispatch')
class ManageUserView(LoginRequiredMixin, ListView):
    model = User
    template_name = 'dashboard/admin/manage_users.html'
    context_object_name = 'users'
    paginate_by = 10

    def get_queryset(self):
        queryset = User.objects.order_by('-id')
        decrypted_users = self.decrypt_user_emails(queryset)
        return decrypted_users

    def decrypt_user_emails(self, queryset):
        decrypted_users = []

        for user in queryset:
            try:
                # Padding the base64-encoded string if needed
                padded_email = user.email + '=' * ((4 - len(user.email) % 4) % 4)
                decrypted_email = decrypt_data(base64.b64decode(padded_email), key, iv)
                user.temp_decrypted_email = decrypted_email  # Temporary field to store decrypted email
                decrypted_users.append(user)
            except binascii.Error as e:
                # Handle invalid base64-encoded strings
                print(f"Error decoding email for user {user.username}: {e}")

        return decrypted_users


@method_decorator(user_passes_test(is_admin, login_url='login_form'), name='dispatch')
class DeleteUser(SuccessMessageMixin, DeleteView):
    model = User
    template_name = 'dashboard/admin/delete_user.html'
    success_url = reverse_lazy('manage_users')
    success_message = 'User was deleted successfully!'


@ratelimit(key='ip', rate='5/m', block=True)
@login_required(login_url='login_form')
@user_passes_test(is_lecturer, login_url='login_form')
def add_tutorial(request):
    courses = Course.objects.only('id', 'name')
    context = {'courses': courses}
    return render(request, 'dashboard/lecturer/add_tutorial.html', context)


@ratelimit(key='ip', rate='5/m', block=True)
@login_required(login_url='login_form')
@user_passes_test(is_lecturer, login_url='login_form')
def post_tutorial(request):
    if request.method == 'POST':
        title = request.POST['title']
        course_id = request.POST['course_id']
        content = request.POST['content']
        image = request.FILES['thumb']
        video = request.POST['video']
        current_user = request.user
        author_id = current_user.id
        print(author_id)
        print(course_id)
        a = Tutorial(title=title, content=content, image=image, video=video, user_id=author_id, course_id=course_id)
        a.save()
        log = AuditLog(user=request.user.id, datetime=datetime.now(), desc='Tutorial added')
        log.save()
        messages.success(request, 'Tutorial was posted successfully!')
        return redirect('add_tutorial')
    else:
        messages.error(request, 'Tutorial was not posted successfully!')
        return redirect('add_tutorial')


@ratelimit(key='ip', rate='5/m', block=True)
@login_required(login_url='login_form')
@user_passes_test(is_lecturer, login_url='login_form')
def list_tutorial(request):
    tutorials = Tutorial.objects.all().order_by('created_at')
    tutorials = {'tutorials': tutorials}
    return render(request, 'dashboard/lecturer/list_tutorial.html', tutorials)


@method_decorator(user_passes_test(is_lecturer, login_url='login_form'), name='dispatch')
class LecturerTutorialDetail(LoginRequiredMixin, DetailView):
    model = Tutorial
    template_name = 'dashboard/lecturer/tutorial_detail.html'


@method_decorator(user_passes_test(is_lecturer, login_url='login_form'), name='dispatch')
class AddComment(CreateView):
    model = Comments
    form_class = CommentForm
    template_name = 'dashboard/lecturer/add_comment.html'

    def form_valid(self, form):
        form.instance.user = self.request.user
        form.instance.tutorial_id = self.kwargs['pk']
        log = AuditLog(user=self.request.user.id, datetime=datetime.now(), desc='Lecturer comment added')
        log.save()
        return super().form_valid(form)

    success_url = "/lecturer_tutorials/{tutorial_id}"


class AddCommentStudent(CreateView):
    model = Comments
    form_class = CommentForm
    template_name = 'dashboard/student/add_comment.html'

    def form_valid(self, form):
        form.instance.user = self.request.user
        form.instance.tutorial_id = self.kwargs['pk']
        log = AuditLog(user=self.request.user.id, datetime=datetime.now(), desc='Student comment added')
        log.save()
        return super().form_valid(form)

    success_url = "/student_tutorials/{tutorial_id}"


@ratelimit(key='ip', rate='5/m', block=True)
@login_required(login_url='login_form')
@user_passes_test(is_lecturer, login_url='login_form')
def add_notes(request):
    tutorials = Tutorial.objects.only('id', 'title')
    context = {'tutorials': tutorials}
    return render(request, 'dashboard/lecturer/add_notes.html', context)


@ratelimit(key='ip', rate='5/m', block=True)
@login_required(login_url='login_form')
@user_passes_test(is_lecturer, login_url='login_form')
def post_notes(request):
    if request.method == 'POST':
        tutorial_id = request.POST['tutorial_id']
        pdf_file = request.FILES.get('pdf_file')
        ppt_file = request.FILES.get('ppt_file')
        current_user = request.user
        user_id = current_user.id

        if not pdf_file or not ppt_file:
            return HttpResponseBadRequest("Please select PDF and PPT file to be uploaded.")

        # Validate file types
        allowed_pdf_extensions = ['pdf']
        allowed_ppt_extensions = ['ppt', 'pptx']
        max_file_size = 10 * 1024 * 1024  # 10 MB

        def scan_file_for_virus(file_path):
            clamav = ClamdAgnostic()
            scan_result = clamav.scan_file(file_path)
            if 'FOUND' in scan_result:
                raise ValidationError('Virus detected in the file.')

        if pdf_file:
            try:
                validate_pdf = FileExtensionValidator(allowed_extensions=allowed_pdf_extensions)
                validate_pdf(pdf_file)
                scan_file_for_virus(pdf_file.temporary_file_path())
            except ValidationError as e:
                return HttpResponseBadRequest(f"Invalid PDF file: {e}")

            if pdf_file and pdf_file.size > max_file_size:
                return HttpResponseBadRequest("PDF file size exceeds the limit (10 MB).")

        if ppt_file:
            try:
                validate_ppt = FileExtensionValidator(allowed_extensions=allowed_ppt_extensions)
                validate_ppt(ppt_file)
                scan_file_for_virus(ppt_file.temporary_file_path())
            except ValidationError as e:
                return HttpResponseBadRequest(f"Invalid PPT file: {e}")

            if ppt_file and ppt_file.size > max_file_size:
                return HttpResponseBadRequest("PPT file size exceeds the limit (10 MB).")

        a = Notes(ppt_file=ppt_file, pdf_file=pdf_file, user_id=user_id, tutorial_id=tutorial_id)

        a.save()
        log = AuditLog(user=request.user.id, datetime=datetime.now(), desc='Notes added')
        log.save()
        messages.success = (request, 'Notes Was Published Successfully')
        return redirect('add_notes')
    else:
        messages.error = (request, 'Notes Was Not Published Successfully')
        return redirect('add_notes')


@method_decorator(user_passes_test(is_lecturer, login_url='login_form'), name='dispatch')
class AddQuizView(CreateView):
    model = Quiz
    fields = ('name', 'course')
    template_name = 'dashboard/lecturer/add_quiz.html'

    def form_valid(self, form):
        quiz = form.save(commit=False)
        quiz.owner = self.request.user
        quiz.save()
        log = AuditLog(user=self.request.user.id, datetime=datetime.now(), desc='Notes added')
        log.save()
        return redirect('update_quiz', quiz.pk)


@method_decorator(user_passes_test(is_lecturer, login_url='login_form'), name='dispatch')
class UpdateQuizView(UpdateView):
    model = Quiz
    fields = ('name', 'course')
    template_name = 'dashboard/lecturer/update_quiz.html'

    def get_context_data(self, **kwargs):
        kwargs['questions'] = self.get_object().questions.annotate(answers_count=Count('answers'))
        return super().get_context_data(**kwargs)

    def get_queryset(self):
        return self.request.user.quizzes.all()

    def get_success_url(self):
        return reverse('update_quiz', kwargs={'pk': self.object.pk})


@ratelimit(key='ip', rate='5/m', block=True)
@login_required(login_url='login_form')
@user_passes_test(is_lecturer, login_url='login_form')
def add_question(request, pk):
    # By filtering the quiz by the url keyword argument `pk` and by the owner, which is the logged in user,
    # we are protecting this view at the object-level. Meaning only the owner of quiz will be able to add questions
    # to it.
    # calls the Quiz model and get object from that. If that object or model doesn't exist it raise 404 error.
    quiz = get_object_or_404(Quiz, pk=pk, owner=request.user)

    if request.method == 'POST':
        form = QuestionForm(request.POST)
        if form.is_valid():
            question = form.save(commit=False)
            question.quiz = quiz
            question.save()
            log = AuditLog(user=request.user.id, datetime=datetime.now(), desc='Question added')
            log.save()
            return redirect('update_questions', quiz.pk, question.pk)
    else:
        form = QuestionForm()

        return render(request, 'dashboard/lecturer/add_question.html', {'quiz': quiz, 'form': form})


@ratelimit(key='ip', rate='5/m', block=True)
@login_required(login_url='login_form')

@user_passes_test(is_lecturer, login_url='login_form')
def update_question(request, quiz_pk, question_pk):
    # calls the Quiz model and get object from that. If that object or model doesn't exist it raise 404 error.
    quiz = get_object_or_404(Quiz, pk=quiz_pk, owner=request.user)
    # calls the Question model and get object from that. If that object or model doesn't exist it raise 404 error.
    question = get_object_or_404(Question, pk=question_pk, quiz=quiz)

    # to specify format for the answers (min 2 answers, max 10 answers)
    AnswerFormatSet = inlineformset_factory(
        Question,  # parent model
        Answer,  # base model
        formset=BaseAnswerInlineFormSet,
        fields=('text', 'is_correct'),
        min_num=2,
        validate_min=True,
        max_num=10,
        validate_max=True
    )

    if request.method == 'POST':
        form = QuestionForm(request.POST, instance=question)
        formset = AnswerFormatSet(request.POST, instance=question)
        if form.is_valid() and formset.is_valid():
            with transaction.atomic():
                formset.save()
                formset.save()
            log = AuditLog(user=request.user.id, datetime=datetime.now(), desc='Question updated')
            log.save()
            messages.success(request, 'Question And Answers Saved Successfully')
            return redirect('update_quiz', quiz.pk)
    else:
        form = QuestionForm(instance=question)
        formset = AnswerFormatSet(instance=question)
    return render(request, 'dashboard/lecturer/update_questions.html', {
        'quiz': quiz,
        'question': question,
        'form': form,
        'formset': formset
    })


@method_decorator(user_passes_test(is_lecturer, login_url='login_form'), name='dispatch')
class QuizListView(ListView):
    model = Quiz
    ordering = ('name',)
    context_object_name = 'quizzes'
    template_name = 'dashboard/lecturer/list_quiz.html'

    def get_queryset(self):
        queryset = self.request.user.quizzes \
            .select_related('course') \
            .annotate(questions_count=Count('questions', distinct=True)) \
            .annotate(taken_count=Count('taken_quizzes', distinct=True))
        return queryset


@method_decorator(user_passes_test(is_lecturer, login_url='login_form'), name='dispatch')
class DeleteQuestion(DeleteView):
    model = Question
    context_object_name = 'question'
    template_name = 'dashboard/lecturer/delete_question.html'
    pk_url_kwarg = 'question_pk'

    def get_context_data(self, **kwargs):
        question = self.get_object()
        kwargs['quiz'] = question.quiz
        return super().get_context_data(**kwargs)

    def delete(self, request, *args, **kwargs):
        question = self.get_object()
        log = AuditLog(user=request.user.id, datetime=datetime.now(), desc='Question deleted')
        log.save()
        messages.success(request, 'The question was deleted successfully', question.text)
        return super().delete(request, *args, **kwargs)

    def get_queryset(self):
        return Question.objects.filter(quiz__owner=self.request.user)

    def get_success_url(self):
        question = self.get_object()
        return reverse('update_quiz', kwargs={'pk': question.quiz_id})


@method_decorator(user_passes_test(is_lecturer, login_url='login_form'), name='dispatch')
class DeleteQuiz(DeleteView):
    model = Quiz
    context_object_name = 'quiz'
    template_name = 'dashboard/lecturer/delete_quiz.html'
    success_url = reverse_lazy('list_quiz')

    def delete(self, request, *args, **kwargs):
        quiz = self.get_object()
        log = AuditLog(user=request.user.id, datetime=datetime.now(), desc='Quiz updated')
        log.save()
        messages.success(request, 'The quiz %s was deleted with success!' % quiz.name)
        return super().delete(request, *args, **kwargs)

    def get_queryset(self):
        return self.request.user.quizzes.all()


@method_decorator(user_passes_test(is_lecturer, login_url='login_form'), name='dispatch')
class ResultsView(DeleteView):
    model = Quiz
    context_object_name = 'quiz'
    template_name = 'dashboard/lecturer/quiz_results.html'

    def get_context_data(self, **kwargs):
        quiz = self.get_object()
        taken_quizzes = quiz.taken_quizzes.select_related('student__user').order_by('-date')
        total_taken_quizzes = taken_quizzes.count()
        quiz_score = quiz.taken_quizzes.aggregate(average_score=Avg('score'))
        extra_context = {
            'taken_quizzes': taken_quizzes,
            'total_taken_quizzes': total_taken_quizzes,
            'quiz_score': quiz_score
        }

        kwargs.update(extra_context)
        return super().get_context_data(**kwargs)

    def get_queryset(self):
        return self.request.user.quizzes.all()


@ratelimit(key='ip', rate='5/m', block=True)
@login_required(login_url='login_form')
def student_tutorials(request):
    tutorials = Tutorial.objects.all().order_by('created_at')
    context = {'tutorials': tutorials}
    return render(request, 'dashboard/student/student_tutorials.html', context)


class StudentTutorialDetail(LoginRequiredMixin, DetailView):
    model = Tutorial
    template_name = 'dashboard/student/student_tutorial_detail.html'


class StudentQuizListView(ListView):
    model = Quiz
    ordering = ('name',)
    context_object_name = 'quizzes'
    template_name = 'dashboard/student/student_list_quiz.html'

    def get_queryset(self):
        queryset = Quiz.objects.all()
        return queryset


@ratelimit(key='ip', rate='5/m', block=True)
def quiz_view(request, pk):
    quiz = Quiz.objects.get(pk=pk)
    return render(request, 'dashboard/student/quiz_form.html', {'obj': quiz})


@ratelimit(key='ip', rate='5/m', block=True)
def quiz_data_view(request, pk):
    quiz = Quiz.objects.get(pk=pk)
    questions = []
    for q in quiz.get_questions():  # grab list of questions
        answers = []
        for a in q.get_answers():  # grab list of answers
            answers.append(a.text)
        questions.append({str(q): answers})  # assigning each question their answers
    return JsonResponse({
        'quiz_data': questions,
    })


@ratelimit(key='ip', rate='5/m', block=True)
def is_ajax(request):
    return request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest'


@ratelimit(key='ip', rate='5/m', block=True)
def save_quiz_view(request, pk):
    # print(request.POST)
    if is_ajax(request=request):
        questions = []
        data = request.POST
        data_ = dict(data.lists())

        data_.pop('csrfmiddlewaretoken')

        for k in data_.keys():
            print('key: ', k)
            question = Question.objects.get(text=k)
            questions.append(question)

        student = request.user.student
        quiz = Quiz.objects.get(pk=pk)

        score = 0
        total_questions = quiz.questions.count()
        multiplier = 100 / total_questions
        results = []
        correct_answer = None

        for q in questions:
            answer_selected = request.POST.get(q.text)

            if answer_selected != "":
                question_answers = Answer.objects.filter(question=q)
                for answer in question_answers:
                    if (answer_selected == answer.text) and answer.is_correct:
                        score += 1
                        correct_answer = answer.text
                    else:
                        if answer.is_correct:
                            correct_answer = answer.text

                results.append({str(q): {'correct_answer': correct_answer, 'answered': answer_selected}})
            else:
                results.append({str(q): 'not answered'})

        score_ = score * multiplier
        TakenQuiz.objects.create(quiz=quiz, student=student, score=score_)

        if score_ < 50.0:
            messages.warning(request, 'Better luck next time! Your score for the quiz was %s.' % (score_))
            return JsonResponse({'passed': True, 'score': score_, 'results': results})
        else:
            messages.success(request, 'Congratulations! You completed the quiz! You scored %s points.' % (score_))
            return JsonResponse({'passed': False, 'score': score_, 'results': results})


@method_decorator(user_passes_test(is_admin, login_url='login_form'), name='dispatch')
class AuditLogView(ListView):
    model = AuditLog
    ordering = ('id',)
    context_object_name = 'auditlog'
    template_name = 'dashboard/admin/log_view.html'

    def get_queryset(self):
        queryset = AuditLog.objects.all()
        for query in queryset:
            query.datetime = query.datetime.strftime("%c")
        return queryset