"""Adiciona coluna foto em votos

Revision ID: ae12b34c56d7
Revises: 94fee65d8b18
Create Date: 2025-08-21 00:00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ae12b34c56d7'
down_revision = '94fee65d8b18'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('votos', schema=None) as batch_op:
        batch_op.add_column(sa.Column('foto', sa.String(length=255), nullable=True))


def downgrade():
    with op.batch_alter_table('votos', schema=None) as batch_op:
        batch_op.drop_column('foto')


