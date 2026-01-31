<?php
// php/db_setup.php - تشغيله مرة واحدة فقط
require_once 'config.php';

echo "<h2>إعداد قاعدة البيانات</h2>";

try {
    $pdo = connectDB();
    
    // 1. التحقق من الجداول الأساسية
    $tables = ['article', 'service', 'employe', 'commande', 'ligne_commande'];
    
    foreach ($tables as $table) {
        $check = $pdo->query("SHOW TABLES LIKE '$table'")->fetch();
        if (!$check) {
            echo "<p style='color: red;'>❌ جدول $table غير موجود</p>";
        } else {
            echo "<p style='color: green;'>✅ جدول $table موجود</p>";
        }
    }
    
    // 2. إضافة بيانات تجريبية إذا كانت الجداول فارغة
    // المواد
    $articleCount = $pdo->query("SELECT COUNT(*) as count FROM article")->fetch()['count'];
    if ($articleCount == 0) {
        $articles = [
            ['Cahier 96 pages', 100],
            ['Stylo bleu', 200],
            ['Règle 30cm', 50],
            ['Crayon de papier', 150],
            ['Gomme', 80],
            ['Feutres de couleur', 60],
            ['Papier A4', 500],
            ['Trousse', 30]
        ];
        
        $stmt = $pdo->prepare("INSERT INTO article (design_art, qte_stock) VALUES (?, ?)");
        foreach ($articles as $article) {
            $stmt->execute($article);
        }
        echo "<p>✅ تم إضافة $articleCount مادة</p>";
    }
    
    // الخدمات
    $serviceCount = $pdo->query("SELECT COUNT(*) as count FROM service")->fetch()['count'];
    if ($serviceCount == 0) {
        $services = [
            [1, 'Mathématiques'],
            [2, 'Informatique'],
            [3, 'Physique-Chimie'],
            [4, 'Sciences de la Vie'],
            [5, 'Administration'],
            [6, 'Bibliothèque']
        ];
        
        $stmt = $pdo->prepare("INSERT INTO service (Id_service, design_ser) VALUES (?, ?)");
        foreach ($services as $service) {
            $stmt->execute($service);
        }
        echo "<p>✅ تم إضافة $serviceCount خدمة</p>";
    }
    
    // 3. التحقق من المستخدمين
    $employeCount = $pdo->query("SELECT COUNT(*) as count FROM employe")->fetch()['count'];
    echo "<p>👥 عدد الموظفين المسجلين: $employeCount</p>";
    
    if ($employeCount > 0) {
        $stmt = $pdo->query("SELECT Matricule, Nom, Prenom, role FROM employe");
        echo "<h3>المستخدمون المتاحون:</h3>";
        echo "<ul>";
        while ($user = $stmt->fetch()) {
            echo "<li>{$user['Matricule']} - {$user['Nom']} {$user['Prenom']} ({$user['role']})</li>";
        }
        echo "</ul>";
    }
    
    echo "<h3 style='color: green;'>✅ إعداد قاعدة البيانات مكتمل</h3>";
    echo "<p>يمكنك الآن <a href='../login.html'>تسجيل الدخول</a></p>";
    
} catch (PDOException $e) {
    echo "<p style='color: red;'>❌ خطأ: " . $e->getMessage() . "</p>";
    echo "<p>تأكد من:</p>";
    echo "<ul>";
    echo "<li>تشغيل خادم MySQL</li>";
    echo "<li>وجود قاعدة بيانات باسم 'app_com'</li>";
    echo "<li>استيراد ملف app_com.sql</li>";
    echo "</ul>";
}
?>