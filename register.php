<?php
session_start();
require 'db.php'; // conexão com banco

// Verifica se o formulário foi enviado
if ($_SERVER['REQUEST_METHOD'] == 'POST') {

    // Pegando os dados enviados pelo formulário
    $username = isset($_POST['username']) ? trim($_POST['username']) : '';
    $email = isset($_POST['email']) ? trim($_POST['email']) : '';
    $password = isset($_POST['password']) ? trim($_POST['password']) : '';

    // Verifica campos vazios
    if (empty($username) || empty($email) || empty($password)) {
        $_SESSION['error'] = "Preencha todos os campos.";
        header("Location: index.php");
        exit;
    }

    // Verifica se email já existe
    $checkEmail = $pdo->prepare("SELECT id FROM users WHERE email = ?");
    $checkEmail->execute([$email]);

    if ($checkEmail->rowCount() > 0) {
        $_SESSION['error'] = "Esse email já está cadastrado.";
        header("Location: index.php");
        exit;
    }

    // Criptografar senha
    $passwordHash = password_hash($password, PASSWORD_DEFAULT);

    // Registrar novo usuário
    $sql = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
    $stmt = $pdo->prepare($sql);

    if ($stmt->execute([$username, $email, $passwordHash])) {
        $_SESSION['success'] = "Cadastro realizado com sucesso! Agora faça login.";
        header("Location: index.php");
        exit;
    } else {
        $_SESSION['error'] = "Erro ao cadastrar. Tente novamente.";
        header("Location: index.php");
        exit;
    }
} else {
    // Se alguém tentar acessar o arquivo diretamente
    header("Location: index.php");
    exit;
}
?>
