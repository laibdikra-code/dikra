<?php
// php/api.php - النسخة المصححة والمؤمنة
declare(strict_types=1);

// إعدادات الوقت
date_default_timezone_set('Africa/Algiers');

// بدء الجلسة بأمان
session_start([
    'cookie_httponly' => true,
    'cookie_secure' => isset($_SERVER['HTTPS']),
    'cookie_samesite' => 'Strict',
    'use_strict_mode' => true,
    'use_only_cookies' => true,
    'cookie_lifetime' => 86400, // 24 ساعة
]);

// رؤوس الأمان
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');

// CORS محدود - فقط للنطاقات المسموح بها
$allowedOrigins = [
    'http://localhost',
    'http://127.0.0.1',
    'https://localhost'
];

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowedOrigins)) {
    header("Access-Control-Allow-Origin: $origin");
} elseif (!empty($origin)) {
    // في بيئة الإنتاج، لا تسمح بأي نطاق غير مصرح به
    http_response_code(403);
    echo json_encode([
        'success' => false,
        'message' => 'نطاق غير مصرح به'
    ]);
    exit;
}

header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');

// معالجة طلبات OPTIONS للـ CORS
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// تحميل ملف التهيئة
require_once 'config.php';

// التحقق من تسجيل الدخول
if (!isset($_SESSION['user_id']) || empty($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode([
        'success' => false,
        'message' => 'غير مصرح بالدخول. يرجى تسجيل الدخول.'
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// التحقق من انتهاء صلاحية الجلسة (30 دقيقة)
$sessionTimeout = 30 * 60; // 30 دقيقة
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > $sessionTimeout)) {
    session_unset();
    session_destroy();
    http_response_code(401);
    echo json_encode([
        'success' => false,
        'message' => 'انتهت الجلسة. يرجى تسجيل الدخول مرة أخرى.'
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// تحديث وقت النشاط الأخير
$_SESSION['last_activity'] = time();

// التحقق من تغيير IP أو User Agent (حماية ضد سرقة الجلسة)
if (isset($_SESSION['user_ip']) && $_SESSION['user_ip'] !== $_SERVER['REMOTE_ADDR']) {
    session_destroy();
    http_response_code(401);
    echo json_encode([
        'success' => false,
        'message' => 'تم اكتشاف نشاط مشبوه. يرجى تسجيل الدخول مرة أخرى.'
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

if (isset($_SESSION['user_agent']) && $_SESSION['user_agent'] !== ($_SERVER['HTTP_USER_AGENT'] ?? '')) {
    session_destroy();
    http_response_code(401);
    echo json_encode([
        'success' => false,
        'message' => 'تم اكتشاف نشاط مشبوه. يرجى تسجيل الدخول مرة أخرى.'
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// التحقق من CSRF Token للطلبات POST
if ($_SERVER['REQUEST_METHOD'] === 'POST' || $_SERVER['REQUEST_METHOD'] === 'PUT' || $_SERVER['REQUEST_METHOD'] === 'DELETE') {
    $headers = getallheaders();
    $csrfToken = $headers['X-CSRF-Token'] ?? $_POST['csrf_token'] ?? '';
    
    if (!verifyCSRFToken($csrfToken)) {
        http_response_code(403);
        echo json_encode([
            'success' => false,
            'message' => 'رمز التحقق غير صالح أو منتهي الصلاحية'
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

// استقبال البيانات المدخلة بأمان
function sanitizeInput($data) {
    if (is_array($data)) {
        return array_map('sanitizeInput', $data);
    }
    
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    return $data;
}

// تنظيف جميع المدخلات
$_GET = array_map('sanitizeInput', $_GET);
$_POST = array_map('sanitizeInput', $_POST);

// استقبال العملية
$action = $_GET['action'] ?? '';
$limit = isset($_GET['limit']) ? min(abs((int)$_GET['limit']), 100) : 50; // الحد الأقصى 100
$page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
$offset = ($page - 1) * $limit;

// التابع الرئيسي
try {
    $pdo = connectDB();
    
    switch ($action) {
        // جلب جميع المواد مع تصفية وتصفح
        case 'getArticles':
            $search = isset($_GET['search']) ? "%" . $_GET['search'] . "%" : "%";
            $category = $_GET['category'] ?? null;
            $minStock = isset($_GET['min_stock']) ? (int)$_GET['min_stock'] : null;
            $maxStock = isset($_GET['max_stock']) ? (int)$_GET['max_stock'] : null;
            
            $query = "
                SELECT 
                    id_article,
                    design_art,
                    qte_stock,
                    categorie,
                    unite,
                    stock_min,
                    DATE_FORMAT(created_at, '%d/%m/%Y %H:%i') as created_at,
                    CASE 
                        WHEN qte_stock < stock_min THEN 'danger'
                        WHEN qte_stock < (stock_min * 2) THEN 'warning'
                        ELSE 'success'
                    END as stock_status
                FROM article 
                WHERE (design_art LIKE :search OR id_article LIKE :search)
            ";
            
            $params = [
                ':search' => $search,
                ':limit' => $limit,
                ':offset' => $offset
            ];
            
            if ($category) {
                $query .= " AND categorie = :category";
                $params[':category'] = $category;
            }
            
            if ($minStock !== null) {
                $query .= " AND qte_stock >= :min_stock";
                $params[':min_stock'] = $minStock;
            }
            
            if ($maxStock !== null) {
                $query .= " AND qte_stock <= :max_stock";
                $params[':max_stock'] = $maxStock;
            }
            
            $query .= " ORDER BY design_art LIMIT :limit OFFSET :offset";
            
            $stmt = $pdo->prepare($query);
            
            foreach ($params as $key => $value) {
                $paramType = is_int($value) ? PDO::PARAM_INT : PDO::PARAM_STR;
                $stmt->bindValue($key, $value, $paramType);
            }
            
            $stmt->execute();
            $articles = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            // حساب العدد الكلي مع نفس الفلاتر
            $countQuery = "SELECT COUNT(*) as total FROM article WHERE (design_art LIKE :search OR id_article LIKE :search)";
            $countParams = [':search' => $search];
            
            if ($category) {
                $countQuery .= " AND categorie = :category";
                $countParams[':category'] = $category;
            }
            
            if ($minStock !== null) {
                $countQuery .= " AND qte_stock >= :min_stock";
                $countParams[':min_stock'] = $minStock;
            }
            
            if ($maxStock !== null) {
                $countQuery .= " AND qte_stock <= :max_stock";
                $countParams[':max_stock'] = $maxStock;
            }
            
            $countStmt = $pdo->prepare($countQuery);
            $countStmt->execute($countParams);
            $total = $countStmt->fetch(PDO::FETCH_ASSOC)['total'];
            
            // جلب الفئات للمرشح
            $categoriesStmt = $pdo->query("SELECT DISTINCT categorie FROM article WHERE categorie IS NOT NULL ORDER BY categorie");
            $categories = $categoriesStmt->fetchAll(PDO::FETCH_COLUMN);
            
            echo json_encode([
                'success' => true,
                'data' => $articles,
                'categories' => $categories,
                'pagination' => [
                    'total' => (int)$total,
                    'page' => $page,
                    'limit' => $limit,
                    'pages' => ceil($total / $limit),
                    'from' => $offset + 1,
                    'to' => min($offset + $limit, $total)
                ]
            ], JSON_UNESCAPED_UNICODE);
            break;
            
        // جلب جميع الخدمات
        case 'getServices':
            $stmt = $pdo->prepare("
                SELECT 
                    id_service,
                    code_service,
                    design_ser,
                    (SELECT CONCAT(nom, ' ', prenom) FROM employee WHERE id = s.responsable_id) as responsable
                FROM service s
                ORDER BY design_ser
            ");
            $stmt->execute();
            $services = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            echo json_encode([
                'success' => true,
                'data' => $services
            ], JSON_UNESCAPED_UNICODE);
            break;
            
        // جلب الطلبات الخاصة بالمستخدم مع تصفية
        case 'getCommandes':
            $matricule = $_SESSION['user_matricule'];
            $status = $_GET['status'] ?? null;
            $startDate = $_GET['start_date'] ?? null;
            $endDate = $_GET['end_date'] ?? null;
            $serviceId = $_GET['service_id'] ?? null;
            
            $query = "
                SELECT 
                    c.id_commande,
                    c.num_commande,
                    DATE_FORMAT(c.date_com, '%d/%m/%Y') as date_com,
                    DATE_FORMAT(c.date_sortie, '%d/%m/%Y') as date_sortie,
                    s.design_ser as service,
                    s.code_service as service_code,
                    c.statut_service,
                    c.statut_magasin,
                    COUNT(DISTINCT l.id_ligne) as articles_count,
                    SUM(l.qte_dem) as total_qte,
                    SUM(l.qte_acc) as total_qte_acc,
                    e.nom,
                    e.prenom
                FROM commande c
                LEFT JOIN service s ON c.service_id = s.id_service
                LEFT JOIN ligne_commande l ON c.id_commande = l.commande_id
                LEFT JOIN employee e ON c.employee_id = e.id
                WHERE c.employee_id = (
                    SELECT id FROM employee WHERE matricule = :matricule
                )
            ";
            
            $params = [':matricule' => $matricule];
            
            if ($status) {
                if (in_array($status, ['en attente', 'validée', 'refusée'])) {
                    $query .= " AND c.statut_service = :status";
                } elseif (in_array($status, ['préparée', 'livrée', 'annulée'])) {
                    $query .= " AND c.statut_magasin = :status";
                }
                $params[':status'] = $status;
            }
            
            if ($startDate) {
                $query .= " AND c.date_com >= :start_date";
                $params[':start_date'] = $startDate;
            }
            
            if ($endDate) {
                $query .= " AND c.date_com <= :end_date";
                $params[':end_date'] = $endDate;
            }
            
            if ($serviceId && is_numeric($serviceId)) {
                $query .= " AND c.service_id = :service_id";
                $params[':service_id'] = (int)$serviceId;
            }
            
            $query .= " GROUP BY c.id_commande, c.num_commande, c.date_com, c.date_sortie, 
                        s.design_ser, s.code_service, c.statut_service, c.statut_magasin, e.nom, e.prenom
                       ORDER BY c.date_com DESC, c.id_commande DESC
                       LIMIT :limit OFFSET :offset";
            
            $params[':limit'] = $limit;
            $params[':offset'] = $offset;
            
            $stmt = $pdo->prepare($query);
            
            foreach ($params as $key => $value) {
                $paramType = is_int($value) ? PDO::PARAM_INT : PDO::PARAM_STR;
                $stmt->bindValue($key, $value, $paramType);
            }
            
            $stmt->execute();
            $commandes = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            // حساب العدد الكلي لنفس الفلاتر
            $countQuery = "
                SELECT COUNT(DISTINCT c.id_commande) as total
                FROM commande c
                WHERE c.employee_id = (SELECT id FROM employee WHERE matricule = :matricule)
            ";
            
            $countParams = [':matricule' => $matricule];
            
            if ($status) {
                if (in_array($status, ['en attente', 'validée', 'refusée'])) {
                    $countQuery .= " AND c.statut_service = :status";
                } elseif (in_array($status, ['préparée', 'livrée', 'annulée'])) {
                    $countQuery .= " AND c.statut_magasin = :status";
                }
                $countParams[':status'] = $status;
            }
            
            if ($startDate) {
                $countQuery .= " AND c.date_com >= :start_date";
                $countParams[':start_date'] = $startDate;
            }
            
            if ($endDate) {
                $countQuery .= " AND c.date_com <= :end_date";
                $countParams[':end_date'] = $endDate;
            }
            
            if ($serviceId && is_numeric($serviceId)) {
                $countQuery .= " AND c.service_id = :service_id";
                $countParams[':service_id'] = (int)$serviceId;
            }
            
            $countStmt = $pdo->prepare($countQuery);
            $countStmt->execute($countParams);
            $total = $countStmt->fetch(PDO::FETCH_ASSOC)['total'];
            
            echo json_encode([
                'success' => true,
                'data' => $commandes,
                'pagination' => [
                    'total' => (int)$total,
                    'page' => $page,
                    'limit' => $limit,
                    'pages' => ceil($total / $limit)
                ]
            ], JSON_UNESCAPED_UNICODE);
            break;
            
        // جلب إحصائيات لوحة التحكم
        case 'getStats':
            $matricule = $_SESSION['user_matricule'];
            $isAdmin = ($_SESSION['user_role'] === 'admin');
            $isMagasinier = ($_SESSION['user_role'] === 'magasinier');
            
            $stats = [
                'commandes' => 0,
                'commandes_en_attente' => 0,
                'commandes_validees' => 0,
                'commandes_livrees' => 0,
                'rupture' => 0,
                'articles' => 0,
                'stock_total' => 0,
                'stock_valeur' => 0,
                'services' => 0,
                'users' => 0,
                'alertes' => []
            ];
            
            // عدد الطلبات
            if ($isAdmin || $isMagasinier) {
                // للمسؤولين: جميع الطلبات
                $stmt = $pdo->query("SELECT COUNT(*) as count FROM commande");
                $stats['commandes'] = (int)$stmt->fetch(PDO::FETCH_ASSOC)['count'];
                
                $stmt = $pdo->query("SELECT COUNT(*) as count FROM commande WHERE statut_service = 'en attente'");
                $stats['commandes_en_attente'] = (int)$stmt->fetch(PDO::FETCH_ASSOC)['count'];
                
                $stmt = $pdo->query("SELECT COUNT(*) as count FROM commande WHERE statut_service = 'validée'");
                $stats['commandes_validees'] = (int)$stmt->fetch(PDO::FETCH_ASSOC)['count'];
                
                $stmt = $pdo->query("SELECT COUNT(*) as count FROM commande WHERE statut_magasin = 'livrée'");
                $stats['commandes_livrees'] = (int)$stmt->fetch(PDO::FETCH_ASSOC)['count'];
            } else {
                // للموظفين: طلباتهم فقط
                $stmt = $pdo->prepare("
                    SELECT COUNT(*) as count 
                    FROM commande c
                    JOIN employee e ON c.employee_id = e.id
                    WHERE e.matricule = :matricule
                ");
                $stmt->execute([':matricule' => $matricule]);
                $stats['commandes'] = (int)$stmt->fetch(PDO::FETCH_ASSOC)['count'];
                
                $stmt = $pdo->prepare("
                    SELECT COUNT(*) as count 
                    FROM commande c
                    JOIN employee e ON c.employee_id = e.id
                    WHERE e.matricule = :matricule AND c.statut_service = 'en attente'
                ");
                $stmt->execute([':matricule' => $matricule]);
                $stats['commandes_en_attente'] = (int)$stmt->fetch(PDO::FETCH_ASSOC)['count'];
                
                $stmt = $pdo->prepare("
                    SELECT COUNT(*) as count 
                    FROM commande c
                    JOIN employee e ON c.employee_id = e.id
                    WHERE e.matricule = :matricule AND c.statut_service = 'validée'
                ");
                $stmt->execute([':matricule' => $matricule]);
                $stats['commandes_validees'] = (int)$stmt->fetch(PDO::FETCH_ASSOC)['count'];
                
                $stmt = $pdo->prepare("
                    SELECT COUNT(*) as count 
                    FROM commande c
                    JOIN employee e ON c.employee_id = e.id
                    WHERE e.matricule = :matricule AND c.statut_magasin = 'livrée'
                ");
                $stmt->execute([':matricule' => $matricule]);
                $stats['commandes_livrees'] = (int)$stmt->fetch(PDO::FETCH_ASSOC)['count'];
            }
            
            // المواد المنخفضة المخزون (أقل من الحد الأدنى)
            $stmt = $pdo->query("
                SELECT COUNT(*) as count 
                FROM article 
                WHERE qte_stock < stock_min
            ");
            $stats['rupture'] = (int)$stmt->fetch(PDO::FETCH_ASSOC)['count'];
            
            // المواد في حالة إنذار
            $stmt = $pdo->prepare("
                SELECT id_article, design_art, qte_stock, stock_min
                FROM article 
                WHERE qte_stock < stock_min
                ORDER BY qte_stock ASC
                LIMIT 10
            ");
            $stmt->execute();
            $stats['alertes'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            // إجمالي عدد المواد
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM article");
            $stats['articles'] = (int)$stmt->fetch(PDO::FETCH_ASSOC)['count'];
            
            // إجمالي المخزون
            $stmt = $pdo->query("SELECT SUM(qte_stock) as total FROM article");
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            $stats['stock_total'] = (int)($result['total'] ?? 0);
            
            // عدد الخدمات
            $stmt = $pdo->query("SELECT COUNT(*) as count FROM service");
            $stats['services'] = (int)$stmt->fetch(PDO::FETCH_ASSOC)['count'];
            
            // عدد المستخدمين (للمسؤول فقط)
            if ($isAdmin) {
                $stmt = $pdo->query("SELECT COUNT(*) as count FROM employee WHERE is_active = 1");
                $stats['users'] = (int)$stmt->fetch(PDO::FETCH_ASSOC)['count'];
            }
            
            // إحصائيات إضافية للمسؤولين
            if ($isAdmin) {
                // عدد الطلبات في الأسبوع الأخير
                $stmt = $pdo->query("
                    SELECT COUNT(*) as count 
                    FROM commande 
                    WHERE date_com >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
                ");
                $stats['commandes_semaine'] = (int)$stmt->fetch(PDO::FETCH_ASSOC)['count'];
                
                // عدد المستخدمين النشطين اليوم
                $stmt = $pdo->query("
                    SELECT COUNT(DISTINCT employee_id) as count 
                    FROM commande 
                    WHERE date_com >= CURDATE()
                ");
                $stats['users_actifs'] = (int)$stmt->fetch(PDO::FETCH_ASSOC)['count'];
            }
            
            echo json_encode([
                'success' => true,
                'data' => $stats
            ], JSON_UNESCAPED_UNICODE);
            break;
            
        // جلب تفاصيل طلب معين
        case 'getCommandeDetails':
            $commandeId = $_GET['id'] ?? 0;
            
            if (!$commandeId || !is_numeric($commandeId)) {
                http_response_code(400);
                echo json_encode([
                    'success' => false,
                    'message' => 'رقم الطلب غير صالح'
                ], JSON_UNESCAPED_UNICODE);
                break;
            }
            
            $matricule = $_SESSION['user_matricule'];
            $isAdmin = ($_SESSION['user_role'] === 'admin');
            $isMagasinier = ($_SESSION['user_role'] === 'magasinier');
            
            // التحقق من صلاحيات المستخدم
            $checkQuery = "
                SELECT c.id_commande, e.matricule
                FROM commande c
                JOIN employee e ON c.employee_id = e.id
                WHERE c.id_commande = :id
            ";
            
            $checkStmt = $pdo->prepare($checkQuery);
            $checkStmt->execute([':id' => $commandeId]);
            $commandeCheck = $checkStmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$commandeCheck) {
                http_response_code(404);
                echo json_encode([
                    'success' => false,
                    'message' => 'الطلب غير موجود'
                ], JSON_UNESCAPED_UNICODE);
                break;
            }
            
            // إذا لم يكن المستخدم مسؤولاً أو مخزني، تحقق من أن الطلب خاص به
            if (!$isAdmin && !$isMagasinier && $commandeCheck['matricule'] !== $matricule) {
                http_response_code(403);
                echo json_encode([
                    'success' => false,
                    'message' => 'ليس لديك صلاحية لعرض هذا الطلب'
                ], JSON_UNESCAPED_UNICODE);
                break;
            }
            
            // جلب تفاصيل الطلب
            $query = "
                SELECT 
                    c.id_commande,
                    c.num_commande,
                    DATE_FORMAT(c.date_com, '%d/%m/%Y') as date_com,
                    DATE_FORMAT(c.date_sortie, '%d/%m/%Y') as date_sortie,
                    s.design_ser as service,
                    s.code_service as service_code,
                    c.statut_service,
                    c.statut_magasin,
                    c.notes,
                    e.nom,
                    e.prenom,
                    e.matricule,
                    e.fonction,
                    CONCAT(e.nom, ' ', e.prenom) as employe_nom,
                    DATE_FORMAT(c.created_at, '%d/%m/%Y %H:%i') as created_at,
                    DATE_FORMAT(c.updated_at, '%d/%m/%Y %H:%i') as updated_at
                FROM commande c
                LEFT JOIN service s ON c.service_id = s.id_service
                LEFT JOIN employee e ON c.employee_id = e.id
                WHERE c.id_commande = :id
            ";
            
            $stmt = $pdo->prepare($query);
            $stmt->execute([':id' => $commandeId]);
            $commande = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$commande) {
                http_response_code(404);
                echo json_encode([
                    'success' => false,
                    'message' => 'الطلب غير موجود'
                ], JSON_UNESCAPED_UNICODE);
                break;
            }
            
            // جلب مواد الطلب
            $itemsQuery = "
                SELECT 
                    l.id_ligne,
                    l.article_id,
                    a.design_art,
                    a.categorie,
                    a.unite,
                    l.qte_dem,
                    l.qte_acc,
                    l.obs,
                    a.qte_stock as stock_actuel,
                    CASE 
                        WHEN l.qte_acc IS NULL THEN 'en attente'
                        WHEN l.qte_acc = l.qte_dem THEN 'complet'
                        WHEN l.qte_acc < l.qte_dem THEN 'partiel'
                        ELSE 'supplémentaire'
                    END as etat_approvisionnement
                FROM ligne_commande l
                LEFT JOIN article a ON l.article_id = a.id_article
                WHERE l.commande_id = :id
                ORDER BY a.design_art
            ";
            
            $itemsStmt = $pdo->prepare($itemsQuery);
            $itemsStmt->execute([':id' => $commandeId]);
            $items = $itemsStmt->fetchAll(PDO::FETCH_ASSOC);
            
            // إحصائيات الطلب
            $statsQuery = "
                SELECT 
                    COUNT(*) as total_items,
                    SUM(l.qte_dem) as total_qte_dem,
                    SUM(l.qte_acc) as total_qte_acc,
                    SUM(CASE WHEN l.qte_acc IS NULL THEN 1 ELSE 0 END) as items_en_attente,
                    SUM(CASE WHEN l.qte_acc = l.qte_dem THEN 1 ELSE 0 END) as items_complets,
                    SUM(CASE WHEN l.qte_acc < l.qte_dem THEN 1 ELSE 0 END) as items_partiels
                FROM ligne_commande l
                WHERE l.commande_id = :id
            ";
            
            $statsStmt = $pdo->prepare($statsQuery);
            $statsStmt->execute([':id' => $commandeId]);
            $commandeStats = $statsStmt->fetch(PDO::FETCH_ASSOC);
            
            echo json_encode([
                'success' => true,
                'data' => [
                    'commande' => $commande,
                    'items' => $items,
                    'stats' => $commandeStats
                ]
            ], JSON_UNESCAPED_UNICODE);
            break;
            
        // جلب سجل نشاط المستخدم
        case 'getActivityLog':
            $userId = $_SESSION['user_id'];
            $days = min(isset($_GET['days']) ? (int)$_GET['days'] : 30, 365);
            
            $query = "
                SELECT 
                    action,
                    table_name,
                    details,
                    ip_address,
                    DATE_FORMAT(created_at, '%d/%m/%Y %H:%i') as created_at
                FROM logs
                WHERE user_id = :user_id
                AND created_at >= DATE_SUB(NOW(), INTERVAL :days DAY)
                ORDER BY created_at DESC
                LIMIT 100
            ";
            
            $stmt = $pdo->prepare($query);
            $stmt->execute([
                ':user_id' => $userId,
                ':days' => $days
            ]);
            
            $activities = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            echo json_encode([
                'success' => true,
                'data' => $activities
            ], JSON_UNESCAPED_UNICODE);
            break;
            
        // جلب الإشعارات
        case 'getNotifications':
            $userId = $_SESSION['user_id'];
            $unreadOnly = isset($_GET['unread']) && $_GET['unread'] === 'true';
            
            $query = "
                SELECT 
                    id_notification,
                    type,
                    titre,
                    message,
                    lien,
                    lue,
                    DATE_FORMAT(created_at, '%d/%m/%Y %H:%i') as created_at
                FROM notification
                WHERE user_id = :user_id
            ";
            
            if ($unreadOnly) {
                $query .= " AND lue = 0";
            }
            
            $query .= " ORDER BY created_at DESC LIMIT 50";
            
            $stmt = $pdo->prepare($query);
            $stmt->execute([':user_id' => $userId]);
            
            $notifications = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            // حساب عدد الإشعارات غير المقروءة
            $countStmt = $pdo->prepare("
                SELECT COUNT(*) as unread_count 
                FROM notification 
                WHERE user_id = :user_id AND lue = 0
            ");
            $countStmt->execute([':user_id' => $userId]);
            $unreadCount = (int)$countStmt->fetch(PDO::FETCH_ASSOC)['unread_count'];
            
            echo json_encode([
                'success' => true,
                'data' => $notifications,
                'unread_count' => $unreadCount
            ], JSON_UNESCAPED_UNICODE);
            break;
            
        // تحديث حالة الإشعار كمقروء
        case 'markNotificationRead':
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                http_response_code(405);
                echo json_encode([
                    'success' => false,
                    'message' => 'الطريقة غير مسموحة'
                ], JSON_UNESCAPED_UNICODE);
                break;
            }
            
            $input = json_decode(file_get_contents('php://input'), true);
            $notificationId = $input['notification_id'] ?? 0;
            $markAll = $input['mark_all'] ?? false;
            
            if (!$notificationId && !$markAll) {
                http_response_code(400);
                echo json_encode([
                    'success' => false,
                    'message' => 'بيانات غير كافية'
                ], JSON_UNESCAPED_UNICODE);
                break;
            }
            
            $userId = $_SESSION['user_id'];
            
            if ($markAll) {
                $stmt = $pdo->prepare("
                    UPDATE notification 
                    SET lue = 1 
                    WHERE user_id = :user_id AND lue = 0
                ");
                $stmt->execute([':user_id' => $userId]);
                $affected = $stmt->rowCount();
                
                echo json_encode([
                    'success' => true,
                    'message' => "تم تحديث $affected إشعار",
                    'affected' => $affected
                ], JSON_UNESCAPED_UNICODE);
            } else {
                $stmt = $pdo->prepare("
                    UPDATE notification 
                    SET lue = 1 
                    WHERE id_notification = :id AND user_id = :user_id
                ");
                $stmt->execute([
                    ':id' => $notificationId,
                    ':user_id' => $userId
                ]);
                $affected = $stmt->rowCount();
                
                if ($affected > 0) {
                    echo json_encode([
                        'success' => true,
                        'message' => 'تم تحديث حالة الإشعار'
                    ], JSON_UNESCAPED_UNICODE);
                } else {
                    http_response_code(404);
                    echo json_encode([
                        'success' => false,
                        'message' => 'الإشعار غير موجود'
                    ], JSON_UNESCAPED_UNICODE);
                }
            }
            break;
            
        default:
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'message' => 'عملية غير معروفة',
                'available_actions' => [
                    'getArticles',
                    'getServices',
                    'getCommandes',
                    'getCommandeDetails',
                    'getStats',
                    'getActivityLog',
                    'getNotifications',
                    'markNotificationRead'
                ]
            ], JSON_UNESCAPED_UNICODE);
    }
    
} catch (PDOException $e) {
    // تسجيل الخطأ بدون عرض تفاصيل للمستخدم
    error_log("خطأ في API: " . $e->getMessage());
    
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'حدث خطأ في الخادم. الرجاء المحاولة لاحقاً.'
    ], JSON_UNESCAPED_UNICODE);
    
} catch (Exception $e) {
    error_log("خطأ عام في API: " . $e->getMessage());
    
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'حدث خطأ غير متوقع. الرجاء المحاولة لاحقاً.'
    ], JSON_UNESCAPED_UNICODE);
}

// دالة التحقق من CSRF Token
function verifyCSRFToken($token) {
    if (!isset($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }
    
    // استخدام hash_equals لمنع هجمات التوقيت
    return hash_equals($_SESSION['csrf_token'], $token);
}
?>