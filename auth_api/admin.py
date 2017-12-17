# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import UserChangeForm
from .models import CustomUser, Team, InvitationLink
from django.utils.translation import ugettext, ugettext_lazy as _



class InvitationInLine(admin.TabularInline):
    model = InvitationLink
    fields = ('code', 'team')
    readonly_fields = ('code', 'team')
    can_delete = False
    can_add = False
    extra = 0

class CustomUserChangeForm(UserChangeForm):
    class Meta(UserChangeForm.Meta):
        model = CustomUser


class CustomUserAdmin(UserAdmin):
    form = CustomUserChangeForm
    list_display = ('email', 'first_name', 'last_name', 'email_verified')
    ordering = ('pk',)
    fieldsets = (
        (None, {'fields': ('email', 'password', 'email_verified', 'password_reset_code')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', )}),
        (_('Membership'), {'fields': ('team',)}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2'),
        }),
    )
    readonly_fields = ('last_login', 'date_joined', 'password_reset_code')
    filter_horizontal = ('team', )
    inlines = (InvitationInLine, )


class UserInLine(admin.TabularInline):
    model = CustomUser.team.through
    extra = 0
    verbose_name_plural = 'Team Members'


class TeamAdmin(admin.ModelAdmin):
    model = Team
    fields = ('name',)
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('name',),
        }),
    )
    inlines = (UserInLine,)


admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Team, TeamAdmin)
