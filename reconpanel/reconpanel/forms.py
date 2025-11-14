"""Form definitions for ReconPanel."""

from __future__ import annotations

from typing import List, Tuple

from flask_wtf import FlaskForm
from wtforms import BooleanField, IntegerField, PasswordField, SelectField, SelectMultipleField, StringField
from wtforms.validators import DataRequired, InputRequired, NumberRange, Optional


class LoginForm(FlaskForm):
    """Authenticate a ReconPanel user."""

    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])


class NewScanForm(FlaskForm):
    """Form used to create a new scan."""

    name = StringField("Scan Name", validators=[Optional()])
    wordlist = SelectField("Wordlist", validators=[InputRequired()])
    line_count = SelectField("Lines to Use", coerce=int, validators=[InputRequired()])

    subfinder_use_all = BooleanField("Enable -all", default=True)
    subfinder_use_silent = BooleanField("Enable -silent", default=True)
    subfinder_use_recursive = BooleanField("Enable -recursive", default=False)

    nuclei_template = SelectField("Template Directory", validators=[InputRequired()])
    nuclei_severities = SelectMultipleField(
        "Severities",
        choices=[
            ("info", "Info"),
            ("low", "Low"),
            ("medium", "Medium"),
            ("high", "High"),
            ("critical", "Critical"),
        ],
        validators=[InputRequired(message="Select at least one severity")],
    )
    nuclei_rate_limit = IntegerField(
        "Rate Limit",
        validators=[Optional(), NumberRange(min=1, max=1000, message="Must be between 1 and 1000")],
    )
    nuclei_concurrency = IntegerField(
        "Concurrency",
        validators=[Optional(), NumberRange(min=1, max=500, message="Must be between 1 and 500")],
    )
    nuclei_fast_mode = BooleanField("Enable -stats")

    def set_wordlist_choices(self, files: List[Tuple[str, str]]) -> None:
        self.wordlist.choices = files

    def set_line_choices(self, options: List[int]) -> None:
        self.line_count.choices = [(opt, str(opt)) for opt in options]

    def set_template_choices(self, templates: List[Tuple[str, str]]) -> None:
        self.nuclei_template.choices = templates
