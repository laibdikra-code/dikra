<?php
// setup.php - تشغيل مرة واحدة للتثبيت
require_once 'config.php';

echo "<!DOCTYPE html>
<html lang='fr'>
<head>
    <meta charset='UTF-8'>
    <title>إعداد النظام</title>
    <style>
        body { font-family: Arial; padding: 20px; }
        .success { color: green; }
        .error { color: red; }
        .warning { color: orange; }
    </style>
</head>
<body>
<h2>إعداد نظام إدارة المخزون</h2>";

try {
    $pdo = connectDB();
    
    // 1. التحقق من الجداول
    $tables = ['article', 'service', 'employe', 'commande', 'ligne_commande'];
    $allTablesExist = true;
    
    foreach ($tables as $table) {
        $check = $pdo->query("SHOW TABLES LIKE '$table'")->fetch();
        if ($check) {
            echo "<p class='success'>✅ جدول $table موجود</p>";
        } else {
            echo "<p class='error'>❌ جدول $table غير موجود</p>";
            $allTablesExist = false;
        }
    }
    
    if (!$allTablesExist) {
        echo "<p class='warning'>⚠️ الرجاء استيراد ملف app_com.sql أولاً</p>";
        echo "<p><a href='login.html'>العودة لتسجيل الدخول</a></p>";
        exit();
    }
    
    // 2. التحقق من بيانات المستخدمين
    $stmt = $pdo->query("SELECT COUNT(*) as count FROM employe");
    $count = $stmt->fetch()['count'];
    
    echo "<p class='success'>👥 عدد الموظفين: $count</p>";
    
    if ($count == 0) {
        // إضافة بيانات تجريبية
        $pdo->exec("INSERT INTO employe (Matricule, Nom, Prenom, Fonction, role) VALUES 
            ('1001', 'Admin', 'System', 'Administrateur', 'admin'),
            ('1002', 'Mohamed', 'Ali', 'Professeur', 'employe'),
            ('1003', 'Fatima', 'Ahmed', 'Magasinier', 'magasinier'),
            ('1004', 'Ahmed', 'Hassan', 'Professeur', 'employe')");
        
        echo "<p class='success'>✅ تم إضافة 4 مستخدمين تجريبيين</p>";
    }
    
    // 3. إظهار بيانات الدخول
    $stmt = $pdo->query("SELECT Matricule, Nom, Prenom, role FROM employe LIMIT 5");
    echo "<h3>بيانات الدخول المتاحة:</h3>";
    echo "<table border='1' cellpadding='10'>";
    echo "<tr><th>رقم التسجيل</th><th>الاسم</th><th>الدور</th><th>كلمة المرور</th></tr>";
    
    while ($user = $stmt->fetch()) {
        echo "<tr>";
        echo "<td>{$user['Matricule']}</td>";
        echo "<td>{$user['Nom']} {$user['Prenom']}</td>";
        echo "<td>{$user['role']}</td>";
        echo "<td>استخدم رقم التسجيل أو 'admin123'</td>";
        echo "</tr>";
    }
    echo "</table>";
    
    echo "<h3 class='success'>✅ إعداد النظام مكتمل</h3>";
    echo "<p><a href='login.html' style='background: #4361ee; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;'>الانتقال لتسجيل الدخول</a></p>";
    
} catch (PDOException $e) {
    echo "<p class='error'>❌ خطأ في الاتصال بقاعدة البيانات: " . $e->getMessage() . "</p>";
    echo "<p>تأكد من:</p>";
    echo "<ul>";
    echo "<li>تشغيل خادم MySQL/XAMPP/WAMP</li>";
    echo "<li>إنشاء قاعدة بيانات باسم 'app_com'</li>";
    echo "<li>استيراد ملف app_com.sql</li>";
    echo "</ul>";
}

echo "</body></html>";
?>