from passlib.context import CryptContext


CRIPTO = CryptContext(schemes=['bcrypt'], deprecated='auto')


def verify_password(password: str, hash_password: str) -> bool:
    """
    Função para verificar se a senha está correta, comparando a senha em texto puro, informa-
    da pelo usuário, e o hash da senha que estará a salvo no banco de dados durante a criação
    da conta.
    """

    return CRIPTO.verify(secret=password, hash=hash_password)


def generate_hash_password(password: str) -> str:
    """
    Função que gera e retorna o hash da senha.
    """

    return CRIPTO.hash(secret=password)