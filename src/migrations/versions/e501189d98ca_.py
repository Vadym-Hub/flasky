"""empty message

Revision ID: e501189d98ca
Revises: 18d3f69c3704
Create Date: 2020-09-30 19:33:02.481121

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e501189d98ca'
down_revision = '18d3f69c3704'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('about_me', sa.Text(), nullable=True))
    op.add_column('users', sa.Column('avatar_hash', sa.String(length=32), nullable=True))
    op.add_column('users', sa.Column('last_seen', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('location', sa.String(length=64), nullable=True))
    op.add_column('users', sa.Column('member_since', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('name', sa.String(length=64), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'name')
    op.drop_column('users', 'member_since')
    op.drop_column('users', 'location')
    op.drop_column('users', 'last_seen')
    op.drop_column('users', 'avatar_hash')
    op.drop_column('users', 'about_me')
    # ### end Alembic commands ###
