"""ScanResult'ga foydalanuvchi (user) bog'lanishini qo'shish."""
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("scanner", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="scanresult",
            name="user",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="scans",
                to=settings.AUTH_USER_MODEL,
                verbose_name="Foydalanuvchi",
            ),
        ),
        migrations.AddIndex(
            model_name="scanresult",
            index=models.Index(fields=["user", "status"], name="scanner_sca_user_id_4f1c2a_idx"),
        ),
    ]
