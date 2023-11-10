from django.contrib.auth.models import AbstractUser
from django.db import models
from embed_video.fields import EmbedVideoField


# Create your models here.


class User(AbstractUser):
    is_student = models.BooleanField(default=False)
    is_lecturer = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)


class Course(models.Model):
    name = models.CharField(max_length=30)

    def __str__(self):
        return self.name


class Tutorial(models.Model):
    title = models.CharField(max_length=50)
    content = models.TextField()
    image = models.ImageField(upload_to='media', null=True, blank=True)
    course = models.ForeignKey(Course, on_delete=models.CASCADE, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    video = EmbedVideoField(blank=True, null=True)


class Comments(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    tutorial = models.ForeignKey(Tutorial, related_name='comments', on_delete=models.CASCADE)
    content = models.TextField()
    posted_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return '%s - %s' % (self.tutorial.title, self.user.username)


class Notes(models.Model):
    pdf_file = models.FileField(upload_to='', null=True, blank=True)
    ppt_file = models.FileField(upload_to='', null=True, blank=True)
    tutorial = models.ForeignKey(Tutorial, related_name='notes', on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)


class Quiz(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='quizzes')
    name = models.CharField(max_length=255)
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='quizzes')

    def __str__(self):
        return self.name

    def get_questions(self):
        return self.questions.all()     # related name questions in Question model


class Question(models.Model):
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE, related_name='questions')
    text = models.CharField('Question', max_length=255)

    def __str__(self):
        return self.text

    def get_answers(self):
        return self.answers.all()   # related name answers in Answer model


class Answer(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE, related_name='answers')
    text = models.CharField('Answer', max_length=255)
    is_correct = models.BooleanField('Correct answer', default=False)

    def __str__(self):
        return self.text


class Student(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    quizzes = models.ManyToManyField(Quiz, through='TakenQuiz')

    def __str__(self):
        return self.user.username


class Lecturer(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)


class TakenQuiz(models.Model):
    student = models.ForeignKey(Student, on_delete=models.CASCADE, related_name='taken_quizzes')
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE, related_name='taken_quizzes')
    score = models.FloatField()
    date = models.DateTimeField(auto_now_add=True)


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profile_pic = models.ImageField(upload_to='', default='no-img.jpg', blank=True)
    first_name = models.CharField(max_length=255, default='')
    last_name = models.CharField(max_length=255, default='')
    email = models.EmailField(default='none@email.com')
    contact = models.CharField(max_length=255, blank=True, null=True)
    dob = models.DateField(default='24-06-1997')
    bio = models.TextField(default='')

    def __str__(self):
        return self.user.username
