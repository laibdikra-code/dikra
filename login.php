<?php
// login.php - نسخة مختصرة تعمل مع config.php
require_once 'config.php';

header('Content-Type: application/json; charset=utf-8');

// استقبال البيانات
$input = json_decode(file_get_contents('php://input'), true);

if (json_last_error() !== JSON_ERROR_NONE) {
    $input = $_POST;
}

$action = sanitizeInput($input['action'] ?? '');

// ========== تسجيل الدخول ==========
if ($action === 'login') {
    $username = sanitizeInput($input['username'] ?? '', 'string');
    $password = sanitizeInput($input['password'] ?? '', 'password');
    
    if (empty($username) || empty($password)) {
        echo json_encode([
            'success' => false,
            'message' => 'Veuillez remplir tous les champs'
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }
    
    try {
        $pdo = connectDB();
        
        // البحث عن الموظف باستخدام matricule أو email
        $stmt = $pdo->prepare("
            SELECT id, matricule, nom, prenom, email, role, password_hash, is_active
            FROM employee 
            WHERE (matricule = :username OR email = :username)
            AND is_active = 1
            LIMIT 1
        ");
        
        $stmt->execute([':username' => $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user && password_verify($password, $user['password_hash'])) {
            // تحديث بيانات الجلسة
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['user_matricule'] = $user['matricule'];
            $_SESSION['user_name'] = $user['nom'] . ' ' . $user['prenom'];
            $_SESSION['user_email'] = $user['email'];
            $_SESSION['user_role'] = $user['role'];
            $_SESSION['logged_in'] = true;
            $_SESSION['last_activity'] = time();
            
            // تحديث آخر دخول
            $updateStmt = $pdo->prepare("
                UPDATE employee 
                SET last_login = NOW() 
                WHERE id = :id
            ");
            $updateStmt->execute([':id' => $user['id']]);
            
            echo json_encode([
                'success' => true,
                'message' => 'Connexion réussie',
                'user' => [
                    'id' => $user['id'],
                    'matricule' => $user['matricule'],
                    'name' => $user['nom'] . ' ' . $user['prenom'],
                    'email' => $user['email'],
                    'role' => $user['role']
                ],
                'redirect' => ($user['role'] === 'admin') ? 'dashboard.html' : 'index.html'
            ], JSON_UNESCAPED_UNICODE);
            
        } else {
            echo json_encode([
                'success' => false,
                'message' => 'Identifiants incorrects'
            ], JSON_UNESCAPED_UNICODE);
        }
        
    } catch (PDOException $e) {
        echo json_encode([
            'success' => false,
            'message' => 'Erreur de connexion à la base de données'
        ], JSON_UNESCAPED_UNICODE);
    }
}

// ========== تسجيل الخروج ==========
elseif ($action === 'logout') {
    session_unset();
    session_destroy();
    
    echo json_encode([
        'success' => true,
        'message' => 'Déconnexion réussie'
    ], JSON_UNESCAPED_UNICODE);
}

// ========== التحقق من حالة الدخول ==========
elseif ($action === 'check_auth') {
    $authenticated = isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;
    
    $response = [
        'authenticated' => $authenticated
    ];
    
    if ($authenticated) {
        $response['user'] = [
            'id' => $_SESSION['user_id'] ?? null,
            'matricule' => $_SESSION['user_matricule'] ?? null,
            'name' => $_SESSION['user_name'] ?? null,
            'role' => $_SESSION['user_role'] ?? null
        ];
    }
    
    echo json_encode($response, JSON_UNESCAPED_UNICODE);
}

// ========== إنشاء حساب جديد ==========
elseif ($action === 'signup') {
    $name = sanitizeInput($input['name'] ?? '', 'string');
    $username = sanitizeInput($input['username'] ?? '', 'string');
    $password = sanitizeInput($input['password'] ?? '', 'password');
    $role = sanitizeInput($input['role'] ?? 'employe', 'string');
    
    if (empty($name) || empty($username) || empty($password)) {
        echo json_encode([
            'success' => false,
            'message' => 'Tous les champs obligatoires doivent être remplis'
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }
    
    if (strlen($password) < 6) {
        echo json_encode([
            'success' => false,
            'message' => 'Le mot de passe doit contenir au moins 6 caractères'
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }
    
    try {
        $pdo = connectDB();
        
        // التحقق من عدم تكرار اسم المستخدم
        $checkStmt = $pdo->prepare("SELECT id FROM employee WHERE matricule = :username OR email = :username");
        $checkStmt->execute([':username' => $username]);
        
        if ($checkStmt->fetch()) {
            echo json_encode([
                'success' => false,
                'message' => 'Ce nom d\'utilisateur est déjà pris'
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }
        
        // تجهيز كلمة المرور
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        
        // توليد matricule تلقائياً
        $nomParts = explode(' ', $name);
        $nom = $nomParts[0] ?? '';
        $prenom = $nomParts[1] ?? '';
        
        // إدخال المستخدم الجديد
        $stmt = $pdo->prepare("
            INSERT INTO employee (matricule, nom, prenom, email, role, password_hash) 
            VALUES (:matricule, :nom, :prenom, :email, :role, :password_hash)
        ");
        
        // إنشاء matricule فريد
        $matricule = 'USR' . date('Ymd') . rand(100, 999);
        
        $stmt->execute([
            ':matricule' => $matricule,
            ':nom' => $nom,
            ':prenom' => $prenom,
            ':email' => $username,
            ':role' => $role,
            ':password_hash' => $hashedPassword
        ]);
        
        echo json_encode([
            'success' => true,
            'message' => 'Compte créé avec succès',
            'user_id' => $pdo->lastInsertId(),
            'matricule' => $matricule
        ], JSON_UNESCAPED_UNICODE);
        
    } catch (PDOException $e) {
        echo json_encode([
            'success' => false,
            'message' => 'Erreur lors de la création du compte: ' . $e->getMessage()
        ], JSON_UNESCAPED_UNICODE);
    }
}

else {
    echo json_encode([
        'success' => false,
        'message' => 'Action non reconnue'
    ], JSON_UNESCAPED_UNICODE);
}
?><?php
// login.php - نسخة مختصرة تعمل مع config.php
require_once 'config.php';

header('Content-Type: application/json; charset=utf-8');

// استقبال البيانات
$input = json_decode(file_get_contents('php://input'), true);

if (json_last_error() !== JSON_ERROR_NONE) {
    $input = $_POST;
}

$action = sanitizeInput($input['action'] ?? '');

// ========== تسجيل الدخول ==========
if ($action === 'login') {
    $username = sanitizeInput($input['username'] ?? '', 'string');
    $password = sanitizeInput($input['password'] ?? '', 'password');
    
    if (empty($username) || empty($password)) {
        echo json_encode([
            'success' => false,
            'message' => 'Veuillez remplir tous les champs'
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }
    
    try {
        $pdo = connectDB();
        
        // البحث عن الموظف باستخدام matricule أو email
        $stmt = $pdo->prepare("
            SELECT id, matricule, nom, prenom, email, role, password_hash, is_active
            FROM employee 
            WHERE (matricule = :username OR email = :username)
            AND is_active = 1
            LIMIT 1
        ");
        
        $stmt->execute([':username' => $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user && password_verify($password, $user['password_hash'])) {
            // تحديث بيانات الجلسة
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['user_matricule'] = $user['matricule'];
            $_SESSION['user_name'] = $user['nom'] . ' ' . $user['prenom'];
            $_SESSION['user_email'] = $user['email'];
            $_SESSION['user_role'] = $user['role'];
            $_SESSION['logged_in'] = true;
            $_SESSION['last_activity'] = time();
            
            // تحديث آخر دخول
            $updateStmt = $pdo->prepare("
                UPDATE employee 
                SET last_login = NOW() 
                WHERE id = :id
            ");
            $updateStmt->execute([':id' => $user['id']]);
            
            echo json_encode([
                'success' => true,
                'message' => 'Connexion réussie',
                'user' => [
                    'id' => $user['id'],
                    'matricule' => $user['matricule'],
                    'name' => $user['nom'] . ' ' . $user['prenom'],
                    'email' => $user['email'],
                    'role' => $user['role']
                ],
                'redirect' => ($user['role'] === 'admin') ? 'dashboard.html' : 'index.html'
            ], JSON_UNESCAPED_UNICODE);
            
        } else {
            echo json_encode([
                'success' => false,
                'message' => 'Identifiants incorrects'
            ], JSON_UNESCAPED_UNICODE);
        }
        
    } catch (PDOException $e) {
        echo json_encode([
            'success' => false,
            'message' => 'Erreur de connexion à la base de données'
        ], JSON_UNESCAPED_UNICODE);
    }
}

// ========== تسجيل الخروج ==========
elseif ($action === 'logout') {
    session_unset();
    session_destroy();
    
    echo json_encode([
        'success' => true,
        'message' => 'Déconnexion réussie'
    ], JSON_UNESCAPED_UNICODE);
}

// ========== التحقق من حالة الدخول ==========
elseif ($action === 'check_auth') {
    $authenticated = isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;
    
    $response = [
        'authenticated' => $authenticated
    ];
    
    if ($authenticated) {
        $response['user'] = [
            'id' => $_SESSION['user_id'] ?? null,
            'matricule' => $_SESSION['user_matricule'] ?? null,
            'name' => $_SESSION['user_name'] ?? null,
            'role' => $_SESSION['user_role'] ?? null
        ];
    }
    
    echo json_encode($response, JSON_UNESCAPED_UNICODE);
}

// ========== إنشاء حساب جديد ==========
elseif ($action === 'signup') {
    $name = sanitizeInput($input['name'] ?? '', 'string');
    $username = sanitizeInput($input['username'] ?? '', 'string');
    $password = sanitizeInput($input['password'] ?? '', 'password');
    $role = sanitizeInput($input['role'] ?? 'employe', 'string');
    
    if (empty($name) || empty($username) || empty($password)) {
        echo json_encode([
            'success' => false,
            'message' => 'Tous les champs obligatoires doivent être remplis'
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }
    
    if (strlen($password) < 6) {
        echo json_encode([
            'success' => false,
            'message' => 'Le mot de passe doit contenir au moins 6 caractères'
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }
    
    try {
        $pdo = connectDB();
        
        // التحقق من عدم تكرار اسم المستخدم
        $checkStmt = $pdo->prepare("SELECT id FROM employee WHERE matricule = :username OR email = :username");
        $checkStmt->execute([':username' => $username]);
        
        if ($checkStmt->fetch()) {
            echo json_encode([
                'success' => false,
                'message' => 'Ce nom d\'utilisateur est déjà pris'
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }
        
        // تجهيز كلمة المرور
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        
        // توليد matricule تلقائياً
        $nomParts = explode(' ', $name);
        $nom = $nomParts[0] ?? '';
        $prenom = $nomParts[1] ?? '';
        
        // إدخال المستخدم الجديد
        $stmt = $pdo->prepare("
            INSERT INTO employee (matricule, nom, prenom, email, role, password_hash) 
            VALUES (:matricule, :nom, :prenom, :email, :role, :password_hash)
        ");
        
        // إنشاء matricule فريد
        $matricule = 'USR' . date('Ymd') . rand(100, 999);
        
        $stmt->execute([
            ':matricule' => $matricule,
            ':nom' => $nom,
            ':prenom' => $prenom,
            ':email' => $username,
            ':role' => $role,
            ':password_hash' => $hashedPassword
        ]);
        
        echo json_encode([
            'success' => true,
            'message' => 'Compte créé avec succès',
            'user_id' => $pdo->lastInsertId(),
            'matricule' => $matricule
        ], JSON_UNESCAPED_UNICODE);
        
    } catch (PDOException $e) {
        echo json_encode([
            'success' => false,
            'message' => 'Erreur lors de la création du compte: ' . $e->getMessage()
        ], JSON_UNESCAPED_UNICODE);
    }
}

else {
    echo json_encode([
        'success' => false,
        'message' => 'Action non reconnue'
    ], JSON_UNESCAPED_UNICODE);
}
?>