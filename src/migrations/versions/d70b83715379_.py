"""empty message

Revision ID: d70b83715379
Revises: f1edaf47f4c9
Create Date: 2020-09-29 23:38:52.068259

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd70b83715379'
down_revision = 'f1edaf47f4c9'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('confirmed', sa.Boolean(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'confirmed')
    # ### end Alembic commands ###