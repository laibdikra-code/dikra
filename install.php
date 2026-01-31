<?php
// install.php - تشغيل مرة واحدة للتثبيت
if (file_exists('config.php')) {
    die('التطبيق مثبت بالفعل. احذف هذا الملف بعد التثبيت.');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $host = $_POST['host'] ?? 'localhost';
    $dbname = $_POST['dbname'] ?? 'app_com';
    $username = $_POST['username'] ?? 'root';
    $password = $_POST['password'] ?? '';
    
    // اختبار الاتصال بقاعدة البيانات
    try {
        $pdo = new PDO(
            "mysql:host=$host;dbname=$dbname;charset=utf8mb4",
            $username,
            $password
        );
        
        // تنفيذ SQL لإنشاء الجداول
        $sql = file_get_contents('app_com_corrected.sql');
        $pdo->exec($sql);
        
        // إنشاء ملف config.php
        $configContent = "<?php\n// إعدادات قاعدة البيانات\ndefine('DB_HOST', '$host');\ndefine('DB_NAME', '$dbname');\ndefine('DB_USER', '$username');\ndefine('DB_PASS', '$password');\n\n// إعدادات أخرى\ndefine('SITE_NAME', 'نظام إدارة المخزون');\ndefine('SITE_URL', 'http://' . \$_SERVER['HTTP_HOST']);\ndefine('DEBUG_MODE', false);\n?>";
        
        file_put_contents('config.php', $configContent);
        
        echo "✅ التثبيت تم بنجاح! احذف ملف install.php الآن.";
        
    } catch (PDOException $e) {
        echo "❌ خطأ في الاتصال بقاعدة البيانات: " . $e->getMessage();
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>تثبيت النظام</title>
</head>
<body>
    <h2>تثبيت نظام إدارة المخزون</h2>
    <form method="POST">
        <div>
            <label>خادم قاعدة البيانات:</label>
            <input type="text" name="host" value="localhost" required>
        </div>
        <div>
            <label>اسم قاعدة البيانات:</label>
            <input type="text" name="dbname" value="app_com" required>
        </div>
        <div>
            <label>اسم المستخدم:</label>
            <input type="text" name="username" value="root" required>
        </div>
        <div>
            <label>كلمة المرور:</label>
            <input type="password" name="password">
        </div>
        <button type="submit">تثبيت</button>
    </form>
</body>
</html>