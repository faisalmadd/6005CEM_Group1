from captcha.fields import CaptchaField
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError
from django.db import transaction

from pages.models import *


class StudentRegistrationForm(UserCreationForm):
    email = forms.EmailField()
    contact = forms.CharField(max_length=11)
    captcha = CaptchaField()

    class Meta:
        model = User
        fields = ['username', 'email', 'contact', 'password1', 'password2', 'captcha']

    def __init__(self, *args, **kwargs):
        super(StudentRegistrationForm, self).__init__(*args, **kwargs)

    @transaction.atomic
    def save(self):
        user = super().save(commit=False)
        user.is_student = True
        user.save()
        Student.objects.create(user=user)
        return user


class AdminStudentRegistrationForm(UserCreationForm):
    email = forms.EmailField()
    contact = forms.CharField(max_length=11)

    class Meta:
        model = User
        fields = ['username', 'email', 'contact', 'password1', 'password2']

    def __init__(self, *args, **kwargs):
        super(AdminStudentRegistrationForm, self).__init__(*args, **kwargs)

    @transaction.atomic
    def save(self):
        user = super().save(commit=False)
        user.is_student = True
        user.save()
        Student.objects.create(user=user)
        return user


class LecturerRegistrationForm(UserCreationForm):
    email = forms.EmailField()
    contact = forms.CharField(max_length=11)

    class Meta:
        model = User
        fields = ['username', 'email', 'contact', 'password1', 'password2']

    def __init__(self, *args, **kwargs):
        super(LecturerRegistrationForm, self).__init__(*args, **kwargs)

    @transaction.atomic
    def save(self):
        user = super().save(commit=False)
        user.is_lecturer = True
        user.save()
        Lecturer.objects.create(user=user)
        return user


class QuestionForm(forms.ModelForm):
    class Meta:
        model = Question
        fields = ('text', )


class BaseAnswerInlineFormSet(forms.BaseInlineFormSet):
    def clean(self):
        super().clean()

        has_one_correct_answer = False
        for form in self.forms:
            if not form.cleaned_data.get('DELETE', False):
                if form.cleaned_data.get('is_correct', False):
                    has_one_correct_answer = True
                    break
        if not has_one_correct_answer:
            raise ValidationError('Mark at least one answer as correct.', code='no_correct_answer')


class CommentForm(forms.ModelForm):
    class Meta:
        model = Comments
        fields = ('content', )

        widgets = {
            'content': forms.Textarea(attrs={'class': 'form-control'}),
        }
