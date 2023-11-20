from captcha.fields import CaptchaField
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError
from django.db import transaction
from django.core.validators import RegexValidator

from pages.models import *


class StudentRegistrationForm(UserCreationForm):
    email = forms.EmailField()

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

    def __init__(self, *args, **kwargs):
        super(StudentRegistrationForm, self).__init__(*args, **kwargs)

    def clean_email(self):
        email = self.cleaned_data.get('email')
        return email.lower()

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if not username.isalnum():  # Allow only alphanumeric characters
            raise ValidationError(_('Username can only contain letters and numbers.'))
        return username

    @transaction.atomic
    def save(self):
        user = super().save(commit=False)
        user.is_student = True
        user.save()
        Student.objects.create(user=user)
        return user


class AdminStudentRegistrationForm(UserCreationForm):
    email = forms.EmailField()

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

    def __init__(self, *args, **kwargs):
        super(AdminStudentRegistrationForm, self).__init__(*args, **kwargs)

    def clean_email(self):
        email = self.cleaned_data.get('email')
        return email.lower()

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if not username.isalnum():  # Allow only alphanumeric characters
            raise ValidationError(_('Username can only contain letters and numbers.'))
        return username

    @transaction.atomic
    def save(self):
        user = super().save(commit=False)
        user.is_student = True
        user.save()
        Student.objects.create(user=user)
        return user


class LecturerRegistrationForm(UserCreationForm):
    email = forms.EmailField()

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

    def __init__(self, *args, **kwargs):
        super(LecturerRegistrationForm, self).__init__(*args, **kwargs)

    def clean_email(self):
        email = self.cleaned_data.get('email')
        return email.lower()

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if not username.isalnum():  # Allow only alphanumeric characters
            raise ValidationError(_('Username can only contain letters and numbers.'))
        return username

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
        fields = ('text',)


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
        fields = ('content',)

        widgets = {
            'content': forms.Textarea(attrs={'class': 'form-control'}),
        }


class AddCourseForm(forms.ModelForm):
    alphanumeric_validator = RegexValidator(
        regex=r'^[a-zA-Z0-9_ -]+$',
        message='Course name can only contain alphanumeric characters, spaces, hyphens, and underscores.',
        code='invalid course name'
    )
    name = forms.CharField(
        validators=[alphanumeric_validator],
        help_text='Enter the course name(alphanumeric characters, spaces, hyphens, and underscores).',
    )

    class Meta:
        model = Course
        fields = ['name']
