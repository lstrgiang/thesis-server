"""empty message

Revision ID: 5d25a1d5d0a5
Revises: 
Create Date: 2017-07-13 14:45:50.975933

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '5d25a1d5d0a5'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('rsa_key',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('public_modulus', sa.String(), nullable=False),
    sa.Column('public_exponent', sa.String(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('email', sa.String(length=255), nullable=False),
    sa.Column('password', sa.String(length=255), nullable=False),
    sa.Column('bday', sa.DateTime(), nullable=False),
    sa.Column('fullname', sa.String(length=255), nullable=False),
    sa.Column('job', sa.String(length=255), nullable=True),
    sa.Column('country', sa.String(length=255), nullable=True),
    sa.Column('registered_on', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    op.drop_table('users')
    op.add_column('device_list', sa.Column('main_key', sa.String(length=255), nullable=False))
    op.add_column('device_list', sa.Column('otp_exponent', sa.Integer(), nullable=False))
    op.add_column('device_list', sa.Column('otp_modulus', sa.String(length=500), nullable=False))
    op.add_column('device_list', sa.Column('registered_on', sa.DateTime(), nullable=False))
    op.alter_column('device_list', 'backup_key',
               existing_type=sa.VARCHAR(length=255),
               nullable=False)
    op.drop_constraint('device_list_user_id_fkey', 'device_list', type_='foreignkey')
    op.create_foreign_key(None, 'device_list', 'user', ['user_id'], ['id'])
    op.drop_column('device_list', 'is_root')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('device_list', sa.Column('is_root', sa.VARCHAR(length=255), autoincrement=False, nullable=False))
    op.drop_constraint(None, 'device_list', type_='foreignkey')
    op.create_foreign_key('device_list_user_id_fkey', 'device_list', 'users', ['user_id'], ['id'])
    op.alter_column('device_list', 'backup_key',
               existing_type=sa.VARCHAR(length=255),
               nullable=True)
    op.drop_column('device_list', 'registered_on')
    op.drop_column('device_list', 'otp_modulus')
    op.drop_column('device_list', 'otp_exponent')
    op.drop_column('device_list', 'main_key')
    op.create_table('users',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('email', sa.VARCHAR(length=255), autoincrement=False, nullable=False),
    sa.Column('password', sa.VARCHAR(length=255), autoincrement=False, nullable=False),
    sa.Column('bday', postgresql.TIMESTAMP(), autoincrement=False, nullable=False),
    sa.Column('fullname', sa.VARCHAR(length=255), autoincrement=False, nullable=False),
    sa.Column('job', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('country', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
    sa.Column('registered_on', postgresql.TIMESTAMP(), autoincrement=False, nullable=False),
    sa.PrimaryKeyConstraint('id', name='users_pkey'),
    sa.UniqueConstraint('email', name='users_email_key')
    )
    op.drop_table('user')
    op.drop_table('rsa_key')
    # ### end Alembic commands ###
