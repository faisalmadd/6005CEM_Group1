import base64
import binascii

from django.contrib.auth import login, authenticate
from django.contrib import auth
from django.contrib.auth.forms import UserChangeForm
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.messages.views import SuccessMessageMixin
from django.db import transaction
from django.db.models import Count, Avg
from django.forms import inlineformset_factory
from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404, HttpResponse
from django.contrib import messages
from django.urls import reverse_lazy, reverse
from django.views.generic import CreateView, ListView, DeleteView, UpdateView, DetailView
from .models import TakenQuiz, Profile, Quiz, Question, Answer, Student, User, Course, Tutorial, Notes, Comments
from .forms import StudentRegistrationForm, LecturerRegistrationForm, AdminStudentRegistrationForm, QuestionForm, \
    BaseAnswerInlineFormSet, CommentForm
from utils.crypto_utils import encrypt_data, decrypt_data, generate_key, generate_initialization_vector

key = b'\x16sI\x8f9\x05\x12kKdf\x90\xe55\xa2\xbcrd\x94Z\tP?\xa5\xe2l\xa9\x11\xc6&\xab\x1b'
iv = b'Q\x85\xfe`@\xcd\xbc\xf2\x99\x13\x05qy)\x81X'


# Create your views here.
def homepage_view(request, *args, **kwargs):
    return render(request, "home.html", {})


class StudentRegisterView(CreateView):
    model = User
    form_class = StudentRegistrationForm
    template_name = 'register.html'

    def get_context_data(self, **kwargs):
        kwargs['user_type'] = 'student'
        return super().get_context_data(**kwargs)

    def form_valid(self, form):
        # Encrypt email using the generated key and initialization vector
        encrypted_email = encrypt_data(form.cleaned_data['email'], key, iv)
        print(encrypted_email)

        # Save the encrypted email and other form data
        user = form.save()
        user.email = base64.b64encode(encrypted_email).decode('utf-8')  # Encode base64 to store as string in database
        print(user.email)
        user.save()

        decrypted_data = decrypt_data(encrypted_email, key, iv)
        print("Decrypted Data:", decrypted_data)

        messages.success(self.request, f'Hi {user.username}, your account was created successfully!')
        return redirect('home')


class LecturerRegisterView(CreateView):
    model = User
    form_class = LecturerRegistrationForm
    template_name = 'dashboard/admin/add_lecturer.html'

    def get_context_data(self, **kwargs):
        kwargs['user_type'] = 'lecturer'
        return super().get_context_data(**kwargs)

    def form_valid(self, form):
        user = form.save()
        login(self.request, user)
        return redirect('lecturer_dashboard')


class AdminStudentRegisterView(CreateView):
    model = User
    form_class = AdminStudentRegistrationForm
    template_name = 'dashboard/admin/add_student.html'

    def get_context_data(self, **kwargs):
        kwargs['user_type'] = 'student'
        return super().get_context_data(**kwargs)

    def form_valid(self, form):
        user = form.save()
        login(self.request, user)
        # return redirect('learner')
        return redirect('student_dashboard')


def login_form(request):
    return render(request, 'login.html')


def login_view(request, *args, **kwargs):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None and user.is_active:
            auth.login(request, user)
            if user.is_admin or user.is_superuser:
                return redirect('admin_dashboard')
            elif user.is_lecturer:
                return redirect('lecturer_dashboard')
            elif user.is_student:
                return redirect('student_dashboard')
            else:
                return redirect('login_form')
        else:
            messages.info(request, "Invalid Username or Password")
            return redirect('login_form')


def contact_view(request, *args, **kwargs):
    return render(request, "contact.html", {})


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

        Profile.objects.filter(id=user_id).create(user_id=user_id, contact=contact, first_name=first_name, email=email,
                                                  last_name=last_name, bio=bio, dob=dob, profile_pic=profile_pic)
        messages.success(request, 'Your Profile Was Created Successfully')
        return redirect('lecturer_profile')
    else:
        current_user = request.user
        user_id = current_user.id
        users = Profile.objects.filter(user_id=user_id)
        users = {'users': users}
        return render(request, 'dashboard/lecturer/create_profile.html', users)


def lecturer_user_profile(request):
    current_user = request.user
    user_id = current_user.id
    users = Profile.objects.filter(user_id=user_id)
    users = {'users': users}
    return render(request, 'dashboard/lecturer/view_profile.html', users)


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

        Profile.objects.filter(id=user_id).create(user_id=user_id, contact=contact, first_name=first_name, email=email,
                                                  last_name=last_name, bio=bio, dob=dob, profile_pic=profile_pic)
        return redirect('student_profile')
    else:
        current_user = request.user
        user_id = current_user.id
        users = Profile.objects.filter(user_id=user_id)
        users = {'users': users}
        return render(request, 'dashboard/student/create_profile.html', users)


def student_user_profile(request):
    current_user = request.user
    user_id = current_user.id
    users = Profile.objects.filter(user_id=user_id)
    users = {'users': users}
    return render(request, 'dashboard/student/view_profile.html', users)


def student_dashboard(request, *args, **kwargs):
    student = User.objects.filter(is_student=True).count()
    lecturer = User.objects.filter(is_lecturer=True).count()
    course = Course.objects.all().count()
    users = User.objects.all().count()
    context = {'student': student, 'course': course, 'lecturer': lecturer, 'users': users}

    return render(request, "dashboard/student/dashboard.html", context)


def lecturer_dashboard(request, *args, **kwargs):
    student = User.objects.filter(is_student=True).count()
    lecturer = User.objects.filter(is_lecturer=True).count()
    course = Course.objects.all().count()
    users = User.objects.all().count()
    context = {'student': student, 'course': course, 'lecturer': lecturer, 'users': users}

    return render(request, "dashboard/lecturer/dashboard.html", context)


def admin_dashboard(request, *args, **kwargs):
    student = User.objects.filter(is_student=True).count()
    lecturer = User.objects.filter(is_lecturer=True).count()
    course = Course.objects.all().count()
    users = User.objects.all().count()
    context = {'student': student, 'course': course, 'lecturer': lecturer, 'users': users}

    return render(request, "dashboard/admin/dashboard.html", context)


def add_course(request):
    if request.method == 'POST':
        name = request.POST['name']

        a = Course(name=name)
        a.save()
        messages.success(request, 'Successfully Added Course')
        return redirect('add_course')
    else:
        return render(request, 'dashboard/lecturer/add_course.html')


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


class DeleteUser(SuccessMessageMixin, DeleteView):
    model = User
    template_name = 'dashboard/admin/delete_user.html'
    success_url = reverse_lazy('manage_users')
    success_message = 'User was deleted successfully!'


def add_tutorial(request):
    courses = Course.objects.only('id', 'name')
    context = {'courses': courses}
    return render(request, 'dashboard/lecturer/add_tutorial.html', context)


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
        messages.success(request, 'Tutorial was posted successfully!')
        return redirect('add_tutorial')
    else:
        messages.error(request, 'Tutorial was not posted successfully!')
        return redirect('add_tutorial')


def list_tutorial(request):
    tutorials = Tutorial.objects.all().order_by('created_at')
    tutorials = {'tutorials': tutorials}
    return render(request, 'dashboard/lecturer/list_tutorial.html', tutorials)


class LecturerTutorialDetail(LoginRequiredMixin, DetailView):
    model = Tutorial
    template_name = 'dashboard/lecturer/tutorial_detail.html'


class AddComment(CreateView):
    model = Comments
    form_class = CommentForm
    template_name = 'dashboard/lecturer/add_comment.html'

    def form_valid(self, form):
        form.instance.user = self.request.user
        form.instance.tutorial_id = self.kwargs['pk']
        return super().form_valid(form)

    success_url = "/lecturer_tutorials/{tutorial_id}"


class AddCommentStudent(CreateView):
    model = Comments
    form_class = CommentForm
    template_name = 'dashboard/student/add_comment.html'

    def form_valid(self, form):
        form.instance.user = self.request.user
        form.instance.tutorial_id = self.kwargs['pk']
        return super().form_valid(form)

    success_url = "/student_tutorials/{tutorial_id}"


def add_notes(request):
    tutorials = Tutorial.objects.only('id', 'title')
    context = {'tutorials': tutorials}
    return render(request, 'dashboard/lecturer/add_notes.html', context)


def post_notes(request):
    if request.method == 'POST':
        tutorial_id = request.POST['tutorial_id']
        pdf_file = request.FILES['pdf_file']
        ppt_file = request.FILES['ppt_file']
        current_user = request.user
        user_id = current_user.id

        a = Notes(ppt_file=ppt_file, pdf_file=pdf_file, user_id=user_id, tutorial_id=tutorial_id)
        a.save()
        messages.success = (request, 'Notes Was Published Successfully')
        return redirect('add_notes')
    else:
        messages.error = (request, 'Notes Was Not Published Successfully')
        return redirect('add_notes')


class AddQuizView(CreateView):
    model = Quiz
    fields = ('name', 'course')
    template_name = 'dashboard/lecturer/add_quiz.html'

    def form_valid(self, form):
        quiz = form.save(commit=False)
        quiz.owner = self.request.user
        quiz.save()
        return redirect('update_quiz', quiz.pk)


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
            return redirect('update_questions', quiz.pk, question.pk)
    else:
        form = QuestionForm()

        return render(request, 'dashboard/lecturer/add_question.html', {'quiz': quiz, 'form': form})


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
        messages.success(request, 'The question was deleted successfully', question.text)
        return super().delete(request, *args, **kwargs)

    def get_queryset(self):
        return Question.objects.filter(quiz__owner=self.request.user)

    def get_success_url(self):
        question = self.get_object()
        return reverse('update_quiz', kwargs={'pk': question.quiz_id})


class DeleteQuiz(DeleteView):
    model = Quiz
    context_object_name = 'quiz'
    template_name = 'dashboard/lecturer/delete_quiz.html'
    success_url = reverse_lazy('list_quiz')

    def delete(self, request, *args, **kwargs):
        quiz = self.get_object()
        messages.success(request, 'The quiz %s was deleted with success!' % quiz.name)
        return super().delete(request, *args, **kwargs)

    def get_queryset(self):
        return self.request.user.quizzes.all()


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


'''def take_quiz(request, pk):
    quiz = get_object_or_404(Quiz, pk=pk)
    student = request.user.student

    if student.quizzes.filter(pk=pk).exists():
        return render(request, 'dashboard/student/taken_quiz.html')

    total_questions = quiz.questions.count()
    unanswered_questions = student.get_unanswered_questions(quiz)
    total_unanswered_questions = unanswered_questions.count()
    progress = 100 - round(((total_unanswered_questions - 1) / total_questions) * 100)
    question = unanswered_questions.first()

    if request.method == 'POST':
        form = TakeQuizForm(question=question, data=request.POST)
        if form.is_valid():
            with transaction.atomic():
                student_answer = form.save(commit=False)
                student_answer.student = student
                student_answer.save()
                if student.get_unanswered_questions(quiz).exists():
                    return redirect('take_quiz', pk)
                else:
                    correct_answers = student.quiz_answers.filter(answer__question__quiz=quiz, answer__is_correct=True).count()
                    score = round((correct_answers / total_questions) * 100.0, 2)
                    TakenQuiz.objects.create(student=student, quiz=quiz, score=score)
                    if score < 50.0:
                        messages.warning(request, 'Better luck next time! Your score for the quiz was %s.' % (score))
                    else:
                        messages.success(request, 'Congratulations! You completed the quiz! You scored %s points.' % (score))
                    return redirect('student_quiz_list')
    else:
        form = TakeQuizForm(question=question)

    return render(request, 'dashboard/student/quiz_form.html', {
        'quiz': quiz,
        'question': question,
        'form': form,
        'progress': progress
    })'''


def quiz_view(request, pk):
    quiz = Quiz.objects.get(pk=pk)
    return render(request, 'dashboard/student/quiz_form.html', {'obj': quiz})


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


def is_ajax(request):
    return request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest'


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
