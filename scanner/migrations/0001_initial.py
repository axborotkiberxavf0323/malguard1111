"""Boshlang'ich migratsiya (qo'lda yozilgan — `migrate` shu zahoti ishlaydi)."""
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="ScanResult",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("file_name", models.CharField(max_length=255, verbose_name="Fayl nomi")),
                ("file_size", models.BigIntegerField(default=0, verbose_name="Fayl hajmi (bayt)")),
                ("file_type", models.CharField(blank=True, max_length=120, verbose_name="Fayl turi")),
                ("file_md5", models.CharField(db_index=True, max_length=32, verbose_name="MD5")),
                ("file_sha1", models.CharField(blank=True, max_length=40, verbose_name="SHA1")),
                ("file_sha256", models.CharField(db_index=True, max_length=64, verbose_name="SHA256")),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Kutilmoqda"),
                            ("scanning", "Tekshirilmoqda"),
                            ("completed", "Yakunlandi"),
                            ("error", "Xatolik"),
                        ],
                        default="pending",
                        max_length=20,
                        verbose_name="Holat",
                    ),
                ),
                (
                    "verdict",
                    models.CharField(
                        choices=[
                            ("safe", "Xavfsiz"),
                            ("suspicious", "Shubhali"),
                            ("dangerous", "Xavfli"),
                            ("unknown", "Noma'lum"),
                        ],
                        default="unknown",
                        max_length=20,
                        verbose_name="Xulosa",
                    ),
                ),
                ("danger_score", models.PositiveSmallIntegerField(default=0, verbose_name="Xavf darajasi (0-100)")),
                (
                    "source",
                    models.CharField(
                        choices=[("web", "Web sayt"), ("telegram", "Telegram bot"), ("api", "API")],
                        default="web",
                        max_length=20,
                        verbose_name="Manba",
                    ),
                ),
                ("telegram_user_id", models.BigIntegerField(blank=True, null=True)),
                ("telegram_username", models.CharField(blank=True, max_length=100)),
                ("created_at", models.DateTimeField(auto_now_add=True, verbose_name="Yaratildi")),
                ("completed_at", models.DateTimeField(blank=True, null=True, verbose_name="Yakunlandi")),
                ("virustotal_result", models.JSONField(blank=True, null=True)),
                ("hybrid_analysis_result", models.JSONField(blank=True, null=True)),
                ("malwarebazaar_result", models.JSONField(blank=True, null=True)),
                ("summary_uz", models.TextField(blank=True, verbose_name="O'zbekcha xulosa")),
                ("detections", models.JSONField(blank=True, default=list, verbose_name="Aniqlangan tahdidlar")),
                ("error_message", models.TextField(blank=True)),
            ],
            options={
                "verbose_name": "Skan natijasi",
                "verbose_name_plural": "Skan natijalari",
                "ordering": ["-created_at"],
            },
        ),
        migrations.CreateModel(
            name="ScanStatistics",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("date", models.DateField(unique=True, verbose_name="Sana")),
                ("total_scans", models.IntegerField(default=0)),
                ("dangerous_count", models.IntegerField(default=0)),
                ("suspicious_count", models.IntegerField(default=0)),
                ("safe_count", models.IntegerField(default=0)),
                ("web_scans", models.IntegerField(default=0)),
                ("telegram_scans", models.IntegerField(default=0)),
            ],
            options={
                "verbose_name": "Kunlik statistika",
                "verbose_name_plural": "Kunlik statistikalar",
                "ordering": ["-date"],
            },
        ),
        migrations.AddIndex(
            model_name="scanresult",
            index=models.Index(fields=["file_sha256", "status"], name="scanner_sca_file_sh_2b8e0f_idx"),
        ),
        migrations.AddIndex(
            model_name="scanresult",
            index=models.Index(fields=["verdict"], name="scanner_sca_verdict_6c1a3d_idx"),
        ),
    ]
