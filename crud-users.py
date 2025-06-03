import os
import re
import hashlib
import psycopg2
from decouple import config


DROP_TABLE_USERS = "DROP TABLE IF EXISTS users"

USERS_TABLE = """CREATE TABLE users(
    id SERIAL,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(50) NOT NULL,
    password VARCHAR(128) NOT NULL,
    group_role VARCHAR(20) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)"""


def system_clear(function):
    def wrapper(connect, cursor, current_user=None):
        os.system('cls' if os.name == 'nt' else 'clear')
        function(connect, cursor, current_user)
        input("Presiona Enter para continuar...")  # Espera antes de limpiar
        os.system('cls' if os.name == 'nt' else 'clear')
    wrapper.__doc__ = function.__doc__
    return wrapper


def validate_username(username):
    """
    Valida que el nombre de usuario cumpla con los siguientes criterios:
    - Longitud entre 3 y 30 caracteres
    - Solo letras, números, guiones bajos y guiones medios
    - Debe comenzar con una letra
    """
    # Verificar longitud
    if len(username) < 3 or len(username) > 30:
        return False, (
            "El nombre de usuario debe tener entre 3 y 30 caracteres."
        )

    # Verificar que comience con una letra
    if not username[0].isalpha():
        return False, "El nombre de usuario debe comenzar con una letra."

    # Verificar caracteres permitidos
    # (letras, números, guiones bajos y guiones medios)
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_-]*$', username):
        return False, (
            "El nombre de usuario solo puede contener letras, números, "
            "guiones bajos y guiones medios."
        )

    return True, "Nombre de usuario válido."


def validate_email(email):
    """
    Valida que el email cumpla con un formato estándar:
    - Debe tener un formato de correo electrónico válido
    - Longitud máxima de 50 caracteres (según la definición de la tabla)
    """
    # Verificar longitud
    if len(email) > 50:
        return False, "El email no puede exceder los 50 caracteres."

    # Verificar formato de email usando expresión regular
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return False, "El formato del email no es válido."

    return True, "Email válido."


def validate_password(password):
    """
    Valida que la contraseña cumpla con los siguientes criterios:
    - Longitud mínima de 8 caracteres
    - Debe contener al menos una letra mayúscula
    - Debe contener al menos una letra minúscula
    - Debe contener al menos un número
    - Debe contener al menos un carácter especial
    """
    # Verificar longitud
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres."

    # Verificar mayúscula
    if not any(c.isupper() for c in password):
        return False, "La contraseña debe contener al menos una letra mayúscula."

    # Verificar minúscula
    if not any(c.islower() for c in password):
        return False, "La contraseña debe contener al menos una letra minúscula."

    # Verificar número
    if not any(c.isdigit() for c in password):
        return False, "La contraseña debe contener al menos un número."

    # Verificar carácter especial
    special_chars = r'[!@#$%^&*(),.?":{}|<>]'
    if not re.search(special_chars, password):
        return False, "La contraseña debe contener al menos un carácter especial."

    return True, "Contraseña válida."


def validate_group(group):
    """
    Valida que el grupo sea uno de los permitidos:
    - administrador
    - usuario
    - invitado
    """
    valid_groups = ["administrador", "usuario", "invitado"]

    if group.lower() not in valid_groups:
        return False, (
            "El grupo debe ser uno de los siguientes: "
            f"{', '.join(valid_groups)}."
        )

    return True, "Grupo válido."


def hash_password(password):
    """
    Genera un hash seguro para la contraseña utilizando SHA-256
    """
    return hashlib.sha256(password.encode()).hexdigest()


def check_password(hashed_password, user_password):
    """
    Verifica si la contraseña proporcionada coincide con el hash almacenado
    """
    return (
        hashed_password
        == hashlib.sha256(user_password.encode()).hexdigest()
    )


def require_admin(function):
    """
    Decorador que verifica si el usuario actual es administrador
    """
    def wrapper(connect, cursor, current_user):
        if current_user and current_user[4] == "administrador":
            function(connect, cursor, current_user)
        else:
            print(">>>Error: Esta función solo está disponible para "
                  "administradores.")

    wrapper.__doc__ = function.__doc__
    return wrapper


def login(connect, cursor):
    """
    Función para iniciar sesión en el sistema
    """
    print(">>> Iniciar sesión")
    username = input(">>> Username: ")
    password = input(">>> Password: ")

    query = (
        "SELECT id, username, email, password, group_role "
        "FROM users WHERE username = %s"
    )
    cursor.execute(query, (username,))
    user = cursor.fetchone()

    if user and check_password(user[3], password):
        print(f">>> Bienvenido, {user[1]}! Rol: {user[4]}")
        return user
    else:
        print(">>> Error: Credenciales incorrectas.")
        return None


@system_clear
@require_admin
def create_user(connect, cursor, current_user):
    """A) Create user (Admin only)"""
    while True:
        username = input(">>> Username: ")
        is_valid, message = validate_username(username)
        if not is_valid:
            print(f">>> Error: {message}")
            continue

        # Verificar si el usuario ya existe
        query = "SELECT id FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        if cursor.fetchone():
            print(">>> Error: El nombre de usuario ya está en uso.")
            continue
        break

    while True:
        email = input(">>> Email: ")
        is_valid, message = validate_email(email)
        if not is_valid:
            print(f">>> Error: {message}")
            continue

        # Verificar si el email ya existe
        query = "SELECT id FROM users WHERE email = %s"
        cursor.execute(query, (email,))
        if cursor.fetchone():
            print(">>> Error: El email ya está en uso.")
            continue
        break

    while True:
        password = input(">>> Password: ")
        is_valid, message = validate_password(password)
        if not is_valid:
            print(f">>> Error: {message}")
            continue

        password_confirm = input(">>> Confirm password: ")
        if password != password_confirm:
            print(">>> Error: Las contraseñas no coinciden.")
            continue
        break

    while True:
        group = input(">>> Group (administrador/usuario/invitado): ")
        is_valid, message = validate_group(group)
        if not is_valid:
            print(f">>> Error: {message}")
            continue
        break

    # Hash de la contraseña antes de almacenarla
    hashed_password = hash_password(password)

    query = (
        "INSERT INTO users (username, email, password, group_role) "
        "VALUES (%s, %s, %s, %s)"
    )
    values = (username, email, hashed_password, group.lower())
    cursor.execute(query, values)
    connect.commit()
    print(">>> User created.")


@system_clear
def list_users(connect, cursor, current_user):
    """B) List users"""
    print(">>> List users")

    if current_user[4] == "administrador":
        query = "SELECT id, username, email, group_role FROM users"
    else:
        query = "SELECT id, username FROM users"

    cursor.execute(query)
    users = cursor.fetchall()

    if current_user[4] == "administrador":
        for id, username, email, group in users:
            print(f"     >>> {id} - {username} - {email} - {group}")
    else:
        for id, username in users:
            print(f"     >>> {id} - {username}")


def user_exists(function):
    def wrapper(connect, cursor, current_user):
        id = input(">>> Enter user ID: ")

        query = "SELECT id FROM users WHERE id=%s"
        cursor.execute(query, (id,))

        user = cursor.fetchone()
        if user:
            function(id, connect, cursor, current_user)
        else:
            print(">>> User not found.")

    wrapper.__doc__ = function.__doc__
    return wrapper


@system_clear
@user_exists
@require_admin
def update_user(id, connect, cursor, current_user):
    """C) Update user (Admin only)"""
    print(">>> Update user")

    # Obtener información actual del usuario
    query = "SELECT username, email, group_role FROM users WHERE id = %s"
    cursor.execute(query, (id,))
    current_data = cursor.fetchone()

    if not current_data:
        print(">>> Error: Usuario no encontrado.")
        return

    print(
        f">>> Datos actuales: Username: {current_data[0]}, "
        f"Email: {current_data[1]}, Group: {current_data[2]}"
    )

    while True:
        username = input(
            ">>> New username (dejar vacío para mantener actual): "
        )
        if not username:
            username = current_data[0]
            break

        is_valid, message = validate_username(username)
        if not is_valid:
            print(f">>> Error: {message}")
            continue

        # Verificar si el usuario ya existe (excepto el actual)
        query = "SELECT id FROM users WHERE username = %s AND id != %s"
        cursor.execute(query, (username, id))
        if cursor.fetchone():
            print(">>> Error: El nombre de usuario ya está en uso.")
            continue
        break

    while True:
        email = input(">>> New email (dejar vacío para mantener actual): ")
        if not email:
            email = current_data[1]
            break

        is_valid, message = validate_email(email)
        if not is_valid:
            print(f">>> Error: {message}")
            continue

        # Verificar si el email ya existe (excepto el actual)
        query = "SELECT id FROM users WHERE email = %s AND id != %s"
        cursor.execute(query, (email, id))
        if cursor.fetchone():
            print(">>> Error: El email ya está en uso.")
            continue
        break

    change_password_input = input(">>> ¿Cambiar contraseña? (s/n): ")
    change_password = change_password_input.strip().lower() == 's'
    hashed_password = None

    if change_password:
        while True:
            password = input(">>> New password: ")
            is_valid, message = validate_password(password)
            if not is_valid:
                print(f">>> Error: {message}")
                continue

            password_confirm = input(">>> Confirm new password: ")
            if password != password_confirm:
                print(">>> Error: Las contraseñas no coinciden.")
                continue

            hashed_password = hash_password(password)
            break

    while True:
        group = input(
            ">>> New group (administrador/usuario/invitado) "
            "(dejar vacío para mantener actual): "
        )
        if not group:
            group = current_data[2]
            break

        is_valid, message = validate_group(group)
        if not is_valid:
            print(f">>> Error: {message}")
            continue
        break

    if change_password:
        query = (
            "UPDATE users SET username=%s, email=%s, password=%s, "
            "group_role=%s WHERE id=%s"
        )
        values = (username, email, hashed_password, group.lower(), id)
    else:
        query = (
            "UPDATE users SET username=%s, email=%s, group_role=%s "
            "WHERE id=%s"
        )
        values = (username, email, group.lower(), id)

    cursor.execute(query, values)
    connect.commit()
    print(">>> User updated.")


@system_clear
@user_exists
@require_admin
def delete_user(id, connect, cursor, current_user):
    """D) Delete user (Admin only)"""
    print(">>> Delete user")

    # Verificar que no se esté eliminando a sí mismo
    if int(id) == current_user[0]:
        print(">>> Error: No puedes eliminar tu propio usuario.")
        return

    query = "DELETE FROM users WHERE id=%s"
    cursor.execute(query, (id, ))
    connect.commit()

    # Resetear el contador después de eliminar un registro
    reset_query = (
        "SELECT setval('users_id_seq', "
        "(SELECT COALESCE(MAX(id), 0) FROM users), false)"
    )
    cursor.execute(reset_query)
    connect.commit()

    print(">>> User deleted and ID counter reset.")


@system_clear
@require_admin
def delete_all_users(connect, cursor, current_user):
    """E) Delete all users (Admin only)"""
    print(">>> Delete all users")

    confirmation = input(
        "¿Estás seguro de que deseas eliminar TODOS los usuarios "
        "excepto el actual? (s/n): "
    ).strip().lower()
    if confirmation != 's':
        print(">>> Operación cancelada.")
        return

    # Eliminar todos los usuarios excepto el actual
    query = "DELETE FROM users WHERE id != %s"
    cursor.execute(query, (current_user[0],))

    # Resetear el contador después de eliminar todos los registros
    reset_query = "ALTER SEQUENCE users_id_seq RESTART WITH %s"
    cursor.execute(reset_query, (current_user[0] + 1,))

    connect.commit()
    print(">>> All users deleted (except current) and ID counter reset.")


def default(*args, **kwargs):
    print("Invalid option.")


def create_admin_if_not_exists(connect, cursor):
    """
    Crea un usuario administrador por defecto si no existe ningún usuario
    en la base de datos
    """
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]

    if count == 0:
        print(">>> Creando usuario administrador por defecto...")
        hashed_password = hash_password("Admin123!")
        query = (
            "INSERT INTO users (username, email, password, group_role) "
            "VALUES (%s, %s, %s, %s)"
        )
        values = (
            "admin",
            "admin@example.com",
            hashed_password,
            "administrador"
        )
        cursor.execute(query, values)
        connect.commit()
        print(">>> Usuario administrador creado. Username: admin,")
        print("    Password: Admin123!")


if __name__ == "__main__":
    try:
        connect = psycopg2.connect(
            host=config("DB_HOST"),
            port=config("DB_PORT"),
            dbname=config("DB_NAME"),
            user=config("DB_USER"),
            password=config("DB_PASSWORD")
        )

        with connect.cursor() as cursor:
            # Recrear la tabla si es necesario (descomentar para inicializar)
            # cursor.execute(DROP_TABLE_USERS)
            # cursor.execute(USERS_TABLE)

            # Verificar si la tabla existe, si no, crearla
            cursor.execute(
                "SELECT EXISTS (SELECT FROM information_schema.tables "
                "WHERE table_name = 'users')"
            )
            table_exists = cursor.fetchone()[0]

            if not table_exists:
                cursor.execute(USERS_TABLE)
                connect.commit()
                print(">>> Tabla de usuarios creada.")

            # Crear usuario administrador por defecto si no hay usuarios
            create_admin_if_not_exists(connect, cursor)

            # Iniciar sesión
            current_user = None
            while not current_user:
                current_user = login(connect, cursor)

            # Definir opciones según el rol del usuario
            if current_user[4] == "administrador":
                options = {
                    'a': create_user,
                    'b': list_users,
                    'c': update_user,
                    'd': delete_user,
                    'e': delete_all_users,
                }
            elif current_user[4] == "usuario":
                options = {
                    'b': list_users,
                }
            else:  # invitado
                options = {}

            # Menú principal
            while True:
                if options:
                    for function in options.values():
                        print(function.__doc__)

                print("F) Exit")
                option = input("        Choose an option: ").strip().lower()

                if option == 'f' or option == 'exit':
                    print("     ***Exiting***")
                    break

                function = options.get(option, default)
                function(connect, cursor, current_user)

            # Mostrar usuarios al final (solo para administradores)
            if current_user[4] == "administrador":
                print("\nUsers in the database:")
                cursor.execute("SELECT * FROM users")
                for row in cursor.fetchall():
                    print(row)
                print("Total users:", cursor.rowcount)

    except psycopg2.OperationalError as e:
        print(f"Error connecting to the database: {e}")

    finally:
        if 'connect' in locals():
            connect.close()
            print("Connection closed.")
