<?php
// logout.php
session_start();

// إزالة جميع بيانات الجلسة
$_SESSION = array();

// إذا تم تعيين معرف جلسة، قم بإزالة ملف الجلسة
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

// تدمير الجلسة
session_destroy();

// إرجاع رد JSON
header('Content-Type: application/json');
echo json_encode([
    'success' => true,
    'message' => 'Déconnexion réussie'
]);
?>