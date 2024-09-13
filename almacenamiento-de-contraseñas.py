
import bcrypt

# Función para generar el hash de una contraseña
def hash_password(plain_password):
    salt = bcrypt.gensalt()  # Generar un salt único
    hashed_password = bcrypt.hashpw(plain_password.encode('utf-8'), salt)  # Crear el hash
    return hashed_password

# Diccionario para almacenar los usuarios y sus contraseñas hasheadas
user_database = {}

def store_password(username, plain_password):
    hashed_password = hash_password(plain_password)  # Hashear la contraseña
    user_database[username] = hashed_password  # Almacenar el hash en la base de datos
    print(f"Contraseña para el usuario '{username}' almacenada de manera segura.")

# Función para verificar la contraseña
def verify_password(username, plain_password):
    if username in user_database:
        hashed_password = user_database[username]
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)
    else:
        print(f"Usuario '{username}' no encontrado.")
        return False

if __name__ == "__main__":
    # Almacenar contraseñas para varios usuarios
    store_password("usuario1", "miContrasenaSegura123")
    store_password("usuario2", "otraContrasenaDiferente456")
    
    # Intentar verificar contraseñas correctas e incorrectas
    print(f"Verificación de usuario1: {verify_password('usuario1', 'miContrasenaSegura123')}")
    print(f"Verificación de usuario1 con contraseña incorrecta: {verify_password('usuario1', 'contraseñaIncorrecta')}")
    
    print(f"Verificación de usuario2: {verify_password('usuario2', 'otraContrasenaDiferente456')}")
    print(f"Verificación de usuario no registrado: {verify_password('usuario3', 'noRegistrado')}")
