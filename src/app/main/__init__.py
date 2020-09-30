from flask import Blueprint

main = Blueprint('main', __name__)

from . import views, errors
from ..models import Permission


@main.app_context_processor
def inject_permissions():
    """Добавляем класс Permission в контекст шаблона"""
    return dict(Permission=Permission)
