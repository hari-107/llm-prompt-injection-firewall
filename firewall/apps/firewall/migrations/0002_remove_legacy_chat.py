from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [('firewall', '0001_initial')]
    operations = [migrations.RunSQL('DROP TABLE IF EXISTS chat_conversation;', reverse_sql=migrations.RunSQL.noop)]
