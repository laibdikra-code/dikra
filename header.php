<?php
session_start();

// الاتصال بقاعدة البيانات
require_once 'config.php';

// التحقق من تسجيل الدخول
function checkLogin() {
    if (!isset($_SESSION['user_id'])) {
        header('Location: login.html');
        exit();
    }
}

// الحصول على معلومات المستخدم
function getUserInfo($pdo, $user_id) {
    $stmt = $pdo->prepare("SELECT * FROM employee WHERE id = ?");
    $stmt->execute([$user_id]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}
?>
<!DOCTYPE html>
<html lang="fr" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>نظام إدارة المخزون - <?php echo $pageTitle ?? ''; ?></title>
    <link rel="stylesheet" href="css/style.css">
    <?php if (isset($dashboard) && $dashboard): ?>
        <link rel="stylesheet" href="css/dashboard-style.css">
    <?php endif; ?>
</head>
<body>