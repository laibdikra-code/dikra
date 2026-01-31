<?php
// php/order.php - النسخة المصححة والمؤمنة بالكامل
declare(strict_types=1);

// إعدادات الوقت
date_default_timezone_set('Africa/Algiers');

// بدء الجلسة الآمنة
session_start([
    'cookie_httponly' => true,
    'cookie_secure' => isset($_SERVER['HTTPS']),
    'cookie_samesite' => 'Strict',
    'use_strict_mode' => true,
    'use_only_cookies' => true,
    'cookie_lifetime' => 86400, // 24 ساعة
    'gc_maxlifetime' => 1800, // 30 دقيقة
]);

// رؤوس الأمان
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');

// CORS محدود
$allowedOrigins = [
    'http://localhost',
    'http://127.0.0.1',
    'https://localhost'
];

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowedOrigins)) {
    header("Access-Control-Allow-Origin: $origin");
}

header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-CSRF-Token, X-Requested-With');

// معالجة طلبات OPTIONS
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// تحميل ملف التهيئة
require_once 'config.php';

// ==============================================
// 🛡️  التحقق من الأمان الأساسي
// ==============================================

// التحقق من تسجيل الدخول
if (!isLoggedIn()) {
    http_response_code(401);
    echo json_encode([
        'success' => false,
        'message' => 'غير مصرح بالدخول. يرجى تسجيل الدخول أولاً.'
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// استقبال العملية
$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? '';

// معالجة البيانات المرسلة
$input = [];
if ($method === 'POST' || $method === 'PUT' || $method === 'DELETE') {
    $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
    
    if (strpos($contentType, 'application/json') !== false) {
        $input = json_decode(file_get_contents('php://input'), true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'message' => 'بيانات JSON غير صالحة'
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }
    } else {
        $input = $_POST;
    }
    
    $action = $input['action'] ?? $action;
}

// التحقق من CSRF Token للطلبات التي تغير البيانات
if (in_array($method, ['POST', 'PUT', 'DELETE', 'PATCH'])) {
    $headers = getallheaders();
    $csrfToken = $headers['X-CSRF-Token'] ?? $input['csrf_token'] ?? '';
    
    if (!verifyCSRFToken($csrfToken)) {
        http_response_code(403);
        echo json_encode([
            'success' => false,
            'message' => 'رمز التحقق غير صالح أو منتهي الصلاحية'
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

// ==============================================
// 🔧  دوال مساعدة
// ==============================================

/**
 * التحقق من صلاحيات الطلب
 */
function checkOrderPermission(PDO $pdo, int $orderId, string $requiredPermission = 'view'): bool {
    $userId = $_SESSION['user_id'];
    $userRole = $_SESSION['user_role'];
    
    // إذا كان المستخدم مسؤولاً أو مخزني، لديه صلاحيات كاملة
    if ($userRole === 'admin' || $userRole === 'magasinier') {
        return true;
    }
    
    // للموظفين العاديين، التحقق من أن الطلب ملكهم
    $stmt = $pdo->prepare("
        SELECT employee_id 
        FROM commande 
        WHERE id_commande = :order_id
    ");
    $stmt->execute([':order_id' => $orderId]);
    $order = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$order) {
        return false;
    }
    
    // الحصول على معرف الموظف الحالي
    $userStmt = $pdo->prepare("
        SELECT id 
        FROM employee 
        WHERE matricule = :matricule
    ");
    $userStmt->execute([':matricule' => $_SESSION['user_matricule']]);
    $user = $userStmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$user) {
        return false;
    }
    
    return $order['employee_id'] == $user['id'];
}

/**
 * التحقق من صحة المواد في الطلب
 */
function validateOrderItems(PDO $pdo, array $items): array {
    $errors = [];
    $validItems = [];
    $totalItems = 0;
    
    if (empty($items) || !is_array($items)) {
        $errors[] = 'يجب إضافة مواد للطلب';
        return ['valid' => false, 'errors' => $errors];
    }
    
    foreach ($items as $index => $item) {
        if (!isset($item['article_id']) || !isset($item['quantity'])) {
            $errors[] = "المادة رقم " . ($index + 1) . " غير مكتملة";
            continue;
        }
        
        $articleId = (int)$item['article_id'];
        $quantity = (int)$item['quantity'];
        
        if ($articleId <= 0 || $quantity <= 0) {
            $errors[] = "المادة رقم " . ($index + 1) . " بها بيانات غير صالحة";
            continue;
        }
        
        // التحقق من وجود المادة في المخزون
        $stmt = $pdo->prepare("
            SELECT id_article, design_art, qte_stock, stock_min 
            FROM article 
            WHERE id_article = :article_id
        ");
        $stmt->execute([':article_id' => $articleId]);
        $article = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$article) {
            $errors[] = "المادة رقم " . ($index + 1) . " غير موجودة في المخزون";
            continue;
        }
        
        // التحقق من توفر الكمية
        if ($quantity > $article['qte_stock']) {
            $errors[] = "الكمية المطلوبة للمادة '{$article['design_art']}' تتجاوز المخزون المتاح ({$article['qte_stock']})";
            continue;
        }
        
        // تحذير إذا كانت الكمية قريبة من الحد الأدنى
        $remainingStock = $article['qte_stock'] - $quantity;
        if ($remainingStock < $article['stock_min']) {
            $errors[] = "تنبيه: طلب المادة '{$article['design_art']}' سيجعل المخزون أقل من الحد الأدنى";
        }
        
        $validItems[] = [
            'article_id' => $articleId,
            'quantity' => $quantity,
            'article_name' => $article['design_art'],
            'current_stock' => $article['qte_stock']
        ];
        
        $totalItems += $quantity;
    }
    
    return [
        'valid' => empty($errors),
        'errors' => $errors,
        'items' => $validItems,
        'total_items' => $totalItems
    ];
}

/**
 * توليد رقم طلب فريد
 */
function generateOrderNumber(PDO $pdo): string {
    $year = date('Y');
    $month = date('m');
    
    // البحث عن آخر رقم طلب لهذا الشهر
    $stmt = $pdo->prepare("
        SELECT MAX(CAST(SUBSTRING(num_commande, 10) AS UNSIGNED)) as last_number 
        FROM commande 
        WHERE num_commande LIKE CONCAT('CMD-', :year, '-', :month, '-%')
    ");
    
    $stmt->execute([
        ':year' => $year,
        ':month' => $month
    ]);
    
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    $lastNumber = $result['last_number'] ?? 0;
    
    $nextNumber = str_pad($lastNumber + 1, 4, '0', STR_PAD_LEFT);
    
    return "CMD-{$year}-{$month}-{$nextNumber}";
}

/**
 * تسجيل نشاط الطلب
 */
function logOrderActivity(PDO $pdo, string $action, int $orderId, array $details = []): void {
    try {
        $userId = $_SESSION['user_id'] ?? 0;
        
        $stmt = $pdo->prepare("
            INSERT INTO activity_logs (
                user_id,
                action,
                entity_type,
                entity_id,
                details,
                ip_address,
                user_agent
            ) VALUES (
                :user_id,
                :action,
                :entity_type,
                :entity_id,
                :details,
                :ip_address,
                :user_agent
            )
        ");
        
        $stmt->execute([
            ':user_id' => $userId,
            ':action' => $action,
            ':entity_type' => 'commande',
            ':entity_id' => $orderId,
            ':details' => json_encode($details, JSON_UNESCAPED_UNICODE),
            ':ip_address' => $_SERVER['REMOTE_ADDR'],
            ':user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
        ]);
    } catch (Exception $e) {
        error_log("فشل تسجيل نشاط الطلب: " . $e->getMessage());
    }
}

/**
 * إرسال إشعار للخدمة
 */
function sendServiceNotification(PDO $pdo, int $orderId, int $serviceId, string $message): void {
    try {
        // البحث عن مسؤول الخدمة
        $stmt = $pdo->prepare("
            SELECT responsable_id 
            FROM service 
            WHERE id_service = :service_id
        ");
        $stmt->execute([':service_id' => $serviceId]);
        $service = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($service && $service['responsable_id']) {
            $notificationStmt = $pdo->prepare("
                INSERT INTO notifications (
                    user_id,
                    type,
                    title,
                    message,
                    link,
                    created_at
                ) VALUES (
                    :user_id,
                    :type,
                    :title,
                    :message,
                    :link,
                    NOW()
                )
            ");
            
            $notificationStmt->execute([
                ':user_id' => $service['responsable_id'],
                ':type' => 'info',
                ':title' => 'طلب جديد',
                ':message' => $message,
                ':link' => "/order-details.php?id={$orderId}"
            ]);
        }
    } catch (Exception $e) {
        error_log("فشل إرسال إشعار: " . $e->getMessage());
    }
}

// ==============================================
// 🔄  معالجة الطلبات الرئيسية
// ==============================================

try {
    $pdo = connectDB();
    
    switch ($action) {
        case 'create':
            if ($method !== 'POST') {
                http_response_code(405);
                echo json_encode([
                    'success' => false,
                    'message' => 'الطريقة غير مسموحة. استخدم POST'
                ], JSON_UNESCAPED_UNICODE);
                break;
            }
            createOrder($pdo, $input);
            break;
            
        case 'details':
            if ($method !== 'GET') {
                http_response_code(405);
                echo json_encode([
                    'success' => false,
                    'message' => 'الطريقة غير مسموحة. استخدم GET'
                ], JSON_UNESCAPED_UNICODE);
                break;
            }
            $orderId = isset($_GET['id']) ? (int)$_GET['id'] : 0;
            getOrderDetails($pdo, $orderId);
            break;
            
        case 'list':
            if ($method !== 'GET') {
                http_response_code(405);
                echo json_encode([
                    'success' => false,
                    'message' => 'الطريقة غير مسموحة. استخدم GET'
                ], JSON_UNESCAPED_UNICODE);
                break;
            }
            listOrders($pdo);
            break;
            
        case 'update':
            if ($method !== 'PUT' && $method !== 'POST') {
                http_response_code(405);
                echo json_encode([
                    'success' => false,
                    'message' => 'الطريقة غير مسموحة. استخدم PUT أو POST'
                ], JSON_UNESCAPED_UNICODE);
                break;
            }
            $orderId = isset($_GET['id']) ? (int)$_GET['id'] : ($input['order_id'] ?? 0);
            updateOrder($pdo, $orderId, $input);
            break;
            
        case 'delete':
            if ($method !== 'DELETE' && $method !== 'POST') {
                http_response_code(405);
                echo json_encode([
                    'success' => false,
                    'message' => 'الطريقة غير مسموحة. استخدم DELETE أو POST'
                ], JSON_UNESCAPED_UNICODE);
                break;
            }
            $orderId = isset($_GET['id']) ? (int)$_GET['id'] : ($input['order_id'] ?? 0);
            deleteOrder($pdo, $orderId, $input);
            break;
            
        case 'cancel':
            if ($method !== 'POST') {
                http_response_code(405);
                echo json_encode([
                    'success' => false,
                    'message' => 'الطريقة غير مسموحة. استخدم POST'
                ], JSON_UNESCAPED_UNICODE);
                break;
            }
            $orderId = $input['order_id'] ?? 0;
            cancelOrder($pdo, $orderId, $input);
            break;
            
        case 'validate':
            if ($method !== 'POST') {
                http_response_code(405);
                echo json_encode([
                    'success' => false,
                    'message' => 'الطريقة غير مسموحة. استخدم POST'
                ], JSON_UNESCAPED_UNICODE);
                break;
            }
            $orderId = $input['order_id'] ?? 0;
            validateOrder($pdo, $orderId, $input);
            break;
            
        case 'deliver':
            if ($method !== 'POST') {
                http_response_code(405);
                echo json_encode([
                    'success' => false,
                    'message' => 'الطريقة غير مسموحة. استخدم POST'
                ], JSON_UNESCAPED_UNICODE);
                break;
            }
            $orderId = $input['order_id'] ?? 0;
            deliverOrder($pdo, $orderId, $input);
            break;
            
        case 'statistics':
            if ($method !== 'GET') {
                http_response_code(405);
                echo json_encode([
                    'success' => false,
                    'message' => 'الطريقة غير مسموحة. استخدم GET'
                ], JSON_UNESCAPED_UNICODE);
                break;
            }
            getOrderStatistics($pdo);
            break;
            
        default:
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'message' => 'عملية غير معروفة',
                'available_actions' => [
                    'create',
                    'details',
                    'list',
                    'update',
                    'delete',
                    'cancel',
                    'validate',
                    'deliver',
                    'statistics'
                ]
            ], JSON_UNESCAPED_UNICODE);
    }
    
} catch (PDOException $e) {
    error_log("خطأ في قاعدة البيانات - order.php: " . $e->getMessage());
    
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'خطأ في قاعدة البيانات. الرجاء المحاولة لاحقاً.'
    ], JSON_UNESCAPED_UNICODE);
    
} catch (Exception $e) {
    error_log("خطأ في order.php: " . $e->getMessage());
    
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ], JSON_UNESCAPED_UNICODE);
}

// ==============================================
// 📋  دوال إدارة الطلبات
// ==============================================

/**
 * إنشاء طلب جديد
 */
function createOrder(PDO $pdo, array $input): void {
    // التحقق من البيانات المطلوبة
    $serviceId = isset($input['service_id']) ? (int)$input['service_id'] : 0;
    $items = $input['items'] ?? [];
    $notes = trim($input['notes'] ?? '');
    
    if ($serviceId <= 0) {
        throw new Exception('يرجى اختيار خدمة صحيحة');
    }
    
    // التحقق من وجود الخدمة
    $serviceStmt = $pdo->prepare("
        SELECT id_service, design_ser 
        FROM service 
        WHERE id_service = :service_id
    ");
    $serviceStmt->execute([':service_id' => $serviceId]);
    $service = $serviceStmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$service) {
        throw new Exception('الخدمة غير موجودة');
    }
    
    // التحقق من صحة المواد
    $validation = validateOrderItems($pdo, $items);
    if (!$validation['valid']) {
        throw new Exception(implode('\n', $validation['errors']));
    }
    
    // الحصول على معرف الموظف
    $userStmt = $pdo->prepare("
        SELECT id 
        FROM employee 
        WHERE matricule = :matricule
    ");
    $userStmt->execute([':matricule' => $_SESSION['user_matricule']]);
    $user = $userStmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$user) {
        throw new Exception('المستخدم غير موجود');
    }
    
    // بدء معاملة
    $pdo->beginTransaction();
    
    try {
        // توليد رقم الطلب
        $orderNumber = generateOrderNumber($pdo);
        
        // إدخال الطلب الرئيسي
        $orderStmt = $pdo->prepare("
            INSERT INTO commande (
                num_commande,
                date_com,
                employee_id,
                service_id,
                statut_service,
                statut_magasin,
                notes,
                created_at
            ) VALUES (
                :num_commande,
                CURDATE(),
                :employee_id,
                :service_id,
                'en attente',
                'en attente',
                :notes,
                NOW()
            )
        ");
        
        $orderStmt->execute([
            ':num_commande' => $orderNumber,
            ':employee_id' => $user['id'],
            ':service_id' => $serviceId,
            ':notes' => $notes
        ]);
        
        $orderId = $pdo->lastInsertId();
        
        if (!$orderId) {
            throw new Exception('فشل في إنشاء الطلب');
        }
        
        // إدخال مواد الطلب
        foreach ($validation['items'] as $item) {
            $itemStmt = $pdo->prepare("
                INSERT INTO ligne_commande (
                    commande_id,
                    article_id,
                    qte_dem,
                    qte_acc,
                    created_at
                ) VALUES (
                    :commande_id,
                    :article_id,
                    :qte_dem,
                    :qte_acc,
                    NOW()
                )
            ");
            
            $itemStmt->execute([
                ':commande_id' => $orderId,
                ':article_id' => $item['article_id'],
                ':qte_dem' => $item['quantity'],
                ':qte_acc' => 0 // سيتم تعبئته لاحقاً من قبل المخزني
            ]);
            
            // تسجيل خصم الكمية المطلوبة من المخزون المتاح (وليس المخزون الفعلي)
            // هذا يحجز الكمية للطلب
            $updateStockStmt = $pdo->prepare("
                UPDATE article 
                SET qte_reservee = COALESCE(qte_reservee, 0) + :quantity
                WHERE id_article = :article_id
            ");
            
            $updateStockStmt->execute([
                ':quantity' => $item['quantity'],
                ':article_id' => $item['article_id']
            ]);
        }
        
        $pdo->commit();
        
        // تسجيل النشاط
        logOrderActivity($pdo, 'ORDER_CREATED', $orderId, [
            'service_id' => $serviceId,
            'items_count' => count($validation['items']),
            'total_quantity' => $validation['total_items']
        ]);
        
        // إرسال إشعار للخدمة
        $message = "تم إنشاء طلب جديد رقم {$orderNumber} للخدمة {$service['design_ser']}";
        sendServiceNotification($pdo, $orderId, $serviceId, $message);
        
        echo json_encode([
            'success' => true,
            'message' => 'تم إنشاء الطلب بنجاح!',
            'order' => [
                'id' => $orderId,
                'number' => $orderNumber,
                'date' => date('d/m/Y'),
                'service' => $service['design_ser'],
                'items_count' => count($validation['items']),
                'total_quantity' => $validation['total_items']
            ],
            'redirect' => 'order-details.html?id=' . $orderId
        ], JSON_UNESCAPED_UNICODE);
        
    } catch (Exception $e) {
        $pdo->rollBack();
        throw new Exception('فشل في إنشاء الطلب: ' . $e->getMessage());
    }
}

/**
 * الحصول على تفاصيل طلب معين
 */
function getOrderDetails(PDO $pdo, int $orderId): void {
    if ($orderId <= 0) {
        throw new Exception('رقم الطلب غير صالح');
    }
    
    // التحقق من الصلاحيات
    if (!checkOrderPermission($pdo, $orderId)) {
        throw new Exception('ليس لديك صلاحية لعرض هذا الطلب');
    }
    
    // جلب تفاصيل الطلب
    $stmt = $pdo->prepare("
        SELECT 
            c.id_commande,
            c.num_commande,
            DATE_FORMAT(c.date_com, '%d/%m/%Y') as date_com,
            DATE_FORMAT(c.date_sortie, '%d/%m/%Y') as date_sortie,
            s.id_service,
            s.design_ser as service_name,
            s.code_service as service_code,
            c.statut_service,
            c.statut_magasin,
            c.notes,
            e.matricule,
            e.nom as employee_nom,
            e.prenom as employee_prenom,
            e.fonction as employee_fonction,
            e.email as employee_email,
            sr.nom as responsable_nom,
            sr.prenom as responsable_prenom,
            DATE_FORMAT(c.created_at, '%d/%m/%Y %H:%i') as created_at,
            DATE_FORMAT(c.updated_at, '%d/%m/%Y %H:%i') as updated_at
        FROM commande c
        LEFT JOIN service s ON c.service_id = s.id_service
        LEFT JOIN employee e ON c.employee_id = e.id
        LEFT JOIN employee sr ON s.responsable_id = sr.id
        WHERE c.id_commande = :order_id
    ");
    
    $stmt->execute([':order_id' => $orderId]);
    $order = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$order) {
        throw new Exception('الطلب غير موجود');
    }
    
    // جلب مواد الطلب
    $itemsStmt = $pdo->prepare("
        SELECT 
            lc.id_ligne,
            lc.article_id,
            a.design_art as article_name,
            a.categorie,
            a.unite,
            lc.qte_dem as requested_quantity,
            lc.qte_acc as approved_quantity,
            lc.obs as notes,
            a.qte_stock as current_stock,
            a.stock_min as min_stock,
            CASE 
                WHEN lc.qte_acc IS NULL THEN 'en attente'
                WHEN lc.qte_acc = 0 THEN 'refusée'
                WHEN lc.qte_acc < lc.qte_dem THEN 'partielle'
                WHEN lc.qte_acc = lc.qte_dem THEN 'complet'
                ELSE 'supplémentaire'
            END as status,
            CASE 
                WHEN a.qte_stock < a.stock_min THEN 'danger'
                WHEN a.qte_stock < (a.stock_min * 2) THEN 'warning'
                ELSE 'success'
            END as stock_status
        FROM ligne_commande lc
        LEFT JOIN article a ON lc.article_id = a.id_article
        WHERE lc.commande_id = :order_id
        ORDER BY a.design_art
    ");
    
    $itemsStmt->execute([':order_id' => $orderId]);
    $items = $itemsStmt->fetchAll(PDO::FETCH_ASSOC);
    
    // إحصائيات الطلب
    $statsStmt = $pdo->prepare("
        SELECT 
            COUNT(*) as total_items,
            SUM(lc.qte_dem) as total_requested,
            SUM(lc.qte_acc) as total_approved,
            SUM(CASE WHEN lc.qte_acc IS NULL THEN 1 ELSE 0 END) as pending_items,
            SUM(CASE WHEN lc.qte_acc = 0 THEN 1 ELSE 0 END) as rejected_items,
            SUM(CASE WHEN lc.qte_acc > 0 AND lc.qte_acc < lc.qte_dem THEN 1 ELSE 0 END) as partial_items,
            SUM(CASE WHEN lc.qte_acc = lc.qte_dem THEN 1 ELSE 0 END) as complete_items
        FROM ligne_commande lc
        WHERE lc.commande_id = :order_id
    ");
    
    $statsStmt->execute([':order_id' => $orderId]);
    $stats = $statsStmt->fetch(PDO::FETCH_ASSOC);
    
    // تسجيل عرض التفاصيل
    logOrderActivity($pdo, 'ORDER_VIEWED', $orderId);
    
    echo json_encode([
        'success' => true,
        'data' => [
            'order' => $order,
            'items' => $items,
            'statistics' => $stats
        ]
    ], JSON_UNESCAPED_UNICODE);
}

/**
 * قائمة الطلبات مع التصفية
 */
function listOrders(PDO $pdo): void {
    $userRole = $_SESSION['user_role'];
    $matricule = $_SESSION['user_matricule'];
    
    // معلمات التصفية
    $page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
    $limit = isset($_GET['limit']) ? min(max(1, (int)$_GET['limit']), 100) : 20;
    $offset = ($page - 1) * $limit;
    
    $status = $_GET['status'] ?? null;
    $serviceId = isset($_GET['service_id']) ? (int)$_GET['service_id'] : null;
    $startDate = $_GET['start_date'] ?? null;
    $endDate = $_GET['end_date'] ?? null;
    $search = $_GET['search'] ?? null;
    
    // بناء الاستعلام الأساسي
    $query = "
        SELECT 
            c.id_commande,
            c.num_commande,
            DATE_FORMAT(c.date_com, '%d/%m/%Y') as date_com,
            DATE_FORMAT(c.date_sortie, '%d/%m/%Y') as date_sortie,
            s.design_ser as service_name,
            s.code_service as service_code,
            c.statut_service,
            c.statut_magasin,
            e.nom as employee_nom,
            e.prenom as employee_prenom,
            e.matricule,
            COUNT(lc.id_ligne) as items_count,
            SUM(lc.qte_dem) as total_requested,
            SUM(lc.qte_acc) as total_approved,
            DATE_FORMAT(c.created_at, '%d/%m/%Y %H:%i') as created_at
        FROM commande c
        LEFT JOIN service s ON c.service_id = s.id_service
        LEFT JOIN employee e ON c.employee_id = e.id
        LEFT JOIN ligne_commande lc ON c.id_commande = lc.commande_id
    ";
    
    $countQuery = "SELECT COUNT(DISTINCT c.id_commande) as total FROM commande c";
    $whereClauses = [];
    $params = [];
    $countParams = [];
    
    // تحديد الصلاحيات
    if ($userRole !== 'admin' && $userRole !== 'magasinier') {
        $whereClauses[] = "e.matricule = :matricule";
        $params[':matricule'] = $matricule;
        $countParams[':matricule'] = $matricule;
    }
    
    // تطبيق الفلاتر
    if ($status) {
        if (in_array($status, ['en attente', 'validée', 'refusée'])) {
            $whereClauses[] = "c.statut_service = :status";
        } elseif (in_array($status, ['préparée', 'livrée', 'annulée'])) {
            $whereClauses[] = "c.statut_magasin = :status";
        }
        $params[':status'] = $status;
        $countParams[':status'] = $status;
    }
    
    if ($serviceId) {
        $whereClauses[] = "c.service_id = :service_id";
        $params[':service_id'] = $serviceId;
        $countParams[':service_id'] = $serviceId;
    }
    
    if ($startDate) {
        $whereClauses[] = "c.date_com >= :start_date";
        $params[':start_date'] = $startDate;
        $countParams[':start_date'] = $startDate;
    }
    
    if ($endDate) {
        $whereClauses[] = "c.date_com <= :end_date";
        $params[':end_date'] = $endDate;
        $countParams[':end_date'] = $endDate;
    }
    
    if ($search) {
        $whereClauses[] = "(c.num_commande LIKE :search OR e.nom LIKE :search OR e.prenom LIKE :search OR s.design_ser LIKE :search)";
        $searchTerm = "%{$search}%";
        $params[':search'] = $searchTerm;
        $countParams[':search'] = $searchTerm;
    }
    
    // بناء الجزء WHERE
    if (!empty($whereClauses)) {
        $where = " WHERE " . implode(" AND ", $whereClauses);
        $query .= $where;
        $countQuery .= $where;
    }
    
    // إضافة GROUP BY و ORDER BY
    $query .= " GROUP BY c.id_commande, c.num_commande, c.date_com, c.date_sortie, 
                s.design_ser, s.code_service, c.statut_service, c.statut_magasin, 
                e.nom, e.prenom, e.matricule, c.created_at
              ORDER BY c.date_com DESC, c.id_commande DESC
              LIMIT :limit OFFSET :offset";
    
    // تنفيذ استعلام العد
    $countStmt = $pdo->prepare($countQuery);
    foreach ($countParams as $key => $value) {
        $countStmt->bindValue($key, $value);
    }
    $countStmt->execute();
    $totalResult = $countStmt->fetch(PDO::FETCH_ASSOC);
    $total = (int)$totalResult['total'];
    
    // تنفيذ الاستعلام الرئيسي
    $params[':limit'] = $limit;
    $params[':offset'] = $offset;
    
    $stmt = $pdo->prepare($query);
    foreach ($params as $key => $value) {
        $paramType = is_int($value) ? PDO::PARAM_INT : PDO::PARAM_STR;
        $stmt->bindValue($key, $value, $paramType);
    }
    
    $stmt->execute();
    $orders = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // جلب قائمة الخدمات للفلاتر
    $servicesStmt = $pdo->query("SELECT id_service, design_ser FROM service ORDER BY design_ser");
    $services = $servicesStmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo json_encode([
        'success' => true,
        'data' => $orders,
        'services' => $services,
        'pagination' => [
            'total' => $total,
            'page' => $page,
            'limit' => $limit,
            'pages' => ceil($total / $limit),
            'from' => $offset + 1,
            'to' => min($offset + $limit, $total)
        ]
    ], JSON_UNESCAPED_UNICODE);
}

/**
 * تحديث طلب
 */
function updateOrder(PDO $pdo, int $orderId, array $input): void {
    if ($orderId <= 0) {
        throw new Exception('رقم الطلب غير صالح');
    }
    
    // التحقق من الصلاحيات
    if (!checkOrderPermission($pdo, $orderId, 'edit')) {
        throw new Exception('ليس لديك صلاحية لتعديل هذا الطلب');
    }
    
    // التحقق من حالة الطلب (لا يمكن تعديل طلب تمت الموافقة عليه)
    $checkStmt = $pdo->prepare("
        SELECT statut_service 
        FROM commande 
        WHERE id_commande = :order_id
    ");
    $checkStmt->execute([':order_id' => $orderId]);
    $order = $checkStmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$order) {
        throw new Exception('الطلب غير موجود');
    }
    
    if ($order['statut_service'] === 'validée') {
        throw new Exception('لا يمكن تعديل طلب تمت الموافقة عليه');
    }
    
    $serviceId = isset($input['service_id']) ? (int)$input['service_id'] : null;
    $notes = isset($input['notes']) ? trim($input['notes']) : null;
    
    $updates = [];
    $params = [':order_id' => $orderId];
    
    if ($serviceId !== null && $serviceId > 0) {
        // التحقق من وجود الخدمة
        $serviceCheck = $pdo->prepare("SELECT id_service FROM service WHERE id_service = :service_id");
        $serviceCheck->execute([':service_id' => $serviceId]);
        
        if ($serviceCheck->fetch()) {
            $updates[] = "service_id = :service_id";
            $params[':service_id'] = $serviceId;
        }
    }
    
    if ($notes !== null) {
        $updates[] = "notes = :notes";
        $params[':notes'] = $notes;
    }
    
    if (empty($updates)) {
        throw new Exception('لا توجد بيانات للتحديث');
    }
    
    $updates[] = "updated_at = NOW()";
    
    $updateQuery = "UPDATE commande SET " . implode(", ", $updates) . " WHERE id_commande = :order_id";
    
    $stmt = $pdo->prepare($updateQuery);
    $stmt->execute($params);
    
    // تسجيل النشاط
    logOrderActivity($pdo, 'ORDER_UPDATED', $orderId, [
        'service_id' => $serviceId,
        'notes_updated' => $notes !== null
    ]);
    
    echo json_encode([
        'success' => true,
        'message' => 'تم تحديث الطلب بنجاح'
    ], JSON_UNESCAPED_UNICODE);
}

/**
 * حذف طلب
 */
function deleteOrder(PDO $pdo, int $orderId, array $input): void {
    if ($orderId <= 0) {
        throw new Exception('رقم الطلب غير صالح');
    }
    
    // التحقق من الصلاحيات
    $userRole = $_SESSION['user_role'];
    if ($userRole !== 'admin') {
        throw new Exception('فقط المسؤول يمكنه حذف الطلبات');
    }
    
    // التحقق من وجود الطلب
    $checkStmt = $pdo->prepare("
        SELECT num_commande, statut_service, statut_magasin 
        FROM commande 
        WHERE id_commande = :order_id
    ");
    $checkStmt->execute([':order_id' => $orderId]);
    $order = $checkStmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$order) {
        throw new Exception('الطلب غير موجود');
    }
    
    // التحقق من تأكيد الحذف
    $confirm = $input['confirm'] ?? false;
    if (!$confirm) {
        throw new Exception('يرجى تأكيد حذف الطلب');
    }
    
    // بدء معاملة
    $pdo->beginTransaction();
    
    try {
        // إرجاع الكميات المحجوزة إلى المخزون
        $itemsStmt = $pdo->prepare("
            SELECT article_id, qte_dem 
            FROM ligne_commande 
            WHERE commande_id = :order_id
        ");
        $itemsStmt->execute([':order_id' => $orderId]);
        $items = $itemsStmt->fetchAll(PDO::FETCH_ASSOC);
        
        foreach ($items as $item) {
            $updateStockStmt = $pdo->prepare("
                UPDATE article 
                SET qte_reservee = GREATEST(COALESCE(qte_reservee, 0) - :quantity, 0)
                WHERE id_article = :article_id
            ");
            $updateStockStmt->execute([
                ':quantity' => $item['qte_dem'],
                ':article_id' => $item['article_id']
            ]);
        }
        
        // حذف مواد الطلب
        $deleteItemsStmt = $pdo->prepare("DELETE FROM ligne_commande WHERE commande_id = :order_id");
        $deleteItemsStmt->execute([':order_id' => $orderId]);
        
        // حذف الطلب
        $deleteOrderStmt = $pdo->prepare("DELETE FROM commande WHERE id_commande = :order_id");
        $deleteOrderStmt->execute([':order_id' => $orderId]);
        
        $pdo->commit();
        
        // تسجيل النشاط
        logOrderActivity($pdo, 'ORDER_DELETED', $orderId, [
            'order_number' => $order['num_commande']
        ]);
        
        echo json_encode([
            'success' => true,
            'message' => 'تم حذف الطلب بنجاح'
        ], JSON_UNESCAPED_UNICODE);
        
    } catch (Exception $e) {
        $pdo->rollBack();
        throw new Exception('فشل في حذف الطلب: ' . $e->getMessage());
    }
}

/**
 * إلغاء طلب
 */
function cancelOrder(PDO $pdo, int $orderId, array $input): void {
    if ($orderId <= 0) {
        throw new Exception('رقم الطلب غير صالح');
    }
    
    // التحقق من الصلاحيات
    if (!checkOrderPermission($pdo, $orderId, 'cancel')) {
        throw new Exception('ليس لديك صلاحية لإلغاء هذا الطلب');
    }
    
    // التحقق من حالة الطلب
    $checkStmt = $pdo->prepare("
        SELECT statut_service, statut_magasin 
        FROM commande 
        WHERE id_commande = :order_id
    ");
    $checkStmt->execute([':order_id' => $orderId]);
    $order = $checkStmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$order) {
        throw new Exception('الطلب غير موجود');
    }
    
    if ($order['statut_magasin'] === 'livrée') {
        throw new Exception('لا يمكن إلغاء طلب تم تسليمه');
    }
    
    if ($order['statut_service'] === 'annulée') {
        throw new Exception('الطلب ملغي بالفعل');
    }
    
    // سبب الإلغاء
    $reason = trim($input['reason'] ?? '');
    if (empty($reason)) {
        throw new Exception('يرجى تقديم سبب الإلغاء');
    }
    
    // بدء معاملة
    $pdo->beginTransaction();
    
    try {
        // تحديث حالة الطلب
        $updateStmt = $pdo->prepare("
            UPDATE commande 
            SET statut_service = 'annulée',
                notes = CONCAT(COALESCE(notes, ''), '\n\nسبب الإلغاء: ', :reason),
                updated_at = NOW()
            WHERE id_commande = :order_id
        ");
        
        $updateStmt->execute([
            ':order_id' => $orderId,
            ':reason' => $reason
        ]);
        
        // إرجاع الكميات المحجوزة إلى المخزون
        $itemsStmt = $pdo->prepare("
            SELECT article_id, qte_dem 
            FROM ligne_commande 
            WHERE commande_id = :order_id
        ]);
        $itemsStmt->execute([':order_id' => $orderId]);
        $items = $itemsStmt->fetchAll(PDO::FETCH_ASSOC);
        
        foreach ($items as $item) {
            $updateStockStmt = $pdo->prepare("
                UPDATE article 
                SET qte_reservee = GREATEST(COALESCE(qte_reservee, 0) - :quantity, 0)
                WHERE id_article = :article_id
            ");
            $updateStockStmt->execute([
                ':quantity' => $item['qte_dem'],
                ':article_id' => $item['article_id']
            ]);
        }
        
        $pdo->commit();
        
        // تسجيل النشاط
        logOrderActivity($pdo, 'ORDER_CANCELLED', $orderId, [
            'reason' => $reason
        ]);
        
        echo json_encode([
            'success' => true,
            'message' => 'تم إلغاء الطلب بنجاح'
        ], JSON_UNESCAPED_UNICODE);
        
    } catch (Exception $e) {
        $pdo->rollBack();
        throw new Exception('فشل في إلغاء الطلب: ' . $e->getMessage());
    }
}

/**
 * الموافقة على طلب (للمخزني والمسؤول)
 */
function validateOrder(PDO $pdo, int $orderId, array $input): void {
    if ($orderId <= 0) {
        throw new Exception('رقم الطلب غير صالح');
    }
    
    // التحقق من الصلاحيات
    $userRole = $_SESSION['user_role'];
    if ($userRole !== 'magasinier' && $userRole !== 'admin') {
        throw new Exception('فقط المخزني أو المسؤول يمكنه الموافقة على الطلبات');
    }
    
    // التحقق من حالة الطلب
    $checkStmt = $pdo->prepare("
        SELECT statut_service 
        FROM commande 
        WHERE id_commande = :order_id
    ");
    $checkStmt->execute([':order_id' => $orderId]);
    $order = $checkStmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$order) {
        throw new Exception('الطلب غير موجود');
    }
    
    if ($order['statut_service'] === 'validée') {
        throw new Exception('الطلب معتمد بالفعل');
    }
    
    if ($order['statut_service'] === 'annulée') {
        throw new Exception('لا يمكن الموافقة على طلب ملغى');
    }
    
    $action = $input['action_type'] ?? 'approve'; // approve أو reject
    $notes = trim($input['notes'] ?? '');
    
    if (!in_array($action, ['approve', 'reject'])) {
        throw new Exception('نوع الإجراء غير صالح');
    }
    
    $newStatus = $action === 'approve' ? 'validée' : 'refusée';
    
    // معالجة الكميات المعتمدة إذا كان القبول
    if ($action === 'approve') {
        $approvedItems = $input['approved_items'] ?? [];
        
        if (!empty($approvedItems)) {
            $pdo->beginTransaction();
            
            try {
                foreach ($approvedItems as $item) {
                    $itemId = $item['item_id'] ?? 0;
                    $approvedQty = $item['approved_quantity'] ?? 0;
                    $itemNotes = $item['notes'] ?? '';
                    
                    if ($itemId > 0 && $approvedQty >= 0) {
                        $updateItemStmt = $pdo->prepare("
                            UPDATE ligne_commande 
                            SET qte_acc = :qte_acc,
                                obs = :obs,
                                updated_at = NOW()
                            WHERE id_ligne = :item_id
                            AND commande_id = :order_id
                        ");
                        
                        $updateItemStmt->execute([
                            ':qte_acc' => $approvedQty,
                            ':obs' => $itemNotes,
                            ':item_id' => $itemId,
                            ':order_id' => $orderId
                        ]);
                    }
                }
                
                $pdo->commit();
            } catch (Exception $e) {
                $pdo->rollBack();
                throw new Exception('فشل في تحديث الكميات المعتمدة: ' . $e->getMessage());
            }
        }
    }
    
    // تحديث حالة الطلب
    $updateStmt = $pdo->prepare("
        UPDATE commande 
        SET statut_service = :status,
            notes = CONCAT(COALESCE(notes, ''), '\n\nملاحظات الموافقة: ', :notes),
            updated_at = NOW()
        WHERE id_commande = :order_id
    ");
    
    $updateStmt->execute([
        ':status' => $newStatus,
        ':notes' => $notes,
        ':order_id' => $orderId
    ]);
    
    // تسجيل النشاط
    $actionType = $action === 'approve' ? 'ORDER_APPROVED' : 'ORDER_REJECTED';
    logOrderActivity($pdo, $actionType, $orderId, [
        'action' => $action,
        'notes' => $notes
    ]);
    
    echo json_encode([
        'success' => true,
        'message' => $action === 'approve' ? 'تم اعتماد الطلب بنجاح' : 'تم رفض الطلب بنجاح'
    ], JSON_UNESCAPED_UNICODE);
}

/**
 * تسليم طلب (للمخزني)
 */
function deliverOrder(PDO $pdo, int $orderId, array $input): void {
    if ($orderId <= 0) {
        throw new Exception('رقم الطلب غير صالح');
    }
    
    // التحقق من الصلاحيات
    $userRole = $_SESSION['user_role'];
    if ($userRole !== 'magasinier' && $userRole !== 'admin') {
        throw new Exception('فقط المخزني أو المسؤول يمكنه تسليم الطلبات');
    }
    
    // التحقق من حالة الطلب
    $checkStmt = $pdo->prepare("
        SELECT statut_service, statut_magasin 
        FROM commande 
        WHERE id_commande = :order_id
    ");
    $checkStmt->execute([':order_id' => $orderId]);
    $order = $checkStmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$order) {
        throw new Exception('الطلب غير موجود');
    }
    
    if ($order['statut_service'] !== 'validée') {
        throw new Exception('لا يمكن تسليم طلب غير معتمد');
    }
    
    if ($order['statut_magasin'] === 'livrée') {
        throw new Exception('الطلب مسلم بالفعل');
    }
    
    $deliveryNotes = trim($input['delivery_notes'] ?? '');
    
    // بدء معاملة
    $pdo->beginTransaction();
    
    try {
        // خصم الكميات المعتمدة من المخزون الفعلي
        $itemsStmt = $pdo->prepare("
            SELECT article_id, qte_acc 
            FROM ligne_commande 
            WHERE commande_id = :order_id
            AND qte_acc > 0
        ");
        $itemsStmt->execute([':order_id' => $orderId]);
        $items = $itemsStmt->fetchAll(PDO::FETCH_ASSOC);
        
        foreach ($items as $item) {
            // خصم من المخزون الفعلي
            $updateStockStmt = $pdo->prepare("
                UPDATE article 
                SET qte_stock = qte_stock - :quantity,
                    qte_reservee = GREATEST(COALESCE(qte_reservee, 0) - :quantity, 0),
                    updated_at = NOW()
                WHERE id_article = :article_id
                AND qte_stock >= :quantity
            ");
            
            $updateStockStmt->execute([
                ':quantity' => $item['qte_acc'],
                ':article_id' => $item['article_id']
            ]);
            
            if ($updateStockStmt->rowCount() === 0) {
                throw new Exception('المخزون غير كافي لإتمام التسليم');
            }
            
            // تسجيل حركة المخزون
            $movementStmt = $pdo->prepare("
                INSERT INTO mouvement_stock (
                    article_id,
                    type_mouvement,
                    quantite,
                    motif,
                    commande_id,
                    employee_id,
                    created_at
                ) VALUES (
                    :article_id,
                    'sortie',
                    :quantite,
                    :motif,
                    :commande_id,
                    :employee_id,
                    NOW()
                )
            ");
            
            $movementStmt->execute([
                ':article_id' => $item['article_id'],
                ':quantite' => $item['qte_acc'],
                ':motif' => 'تسليم طلب',
                ':commande_id' => $orderId,
                ':employee_id' => $_SESSION['user_id']
            ]);
        }
        
        // تحديث حالة الطلب
        $updateStmt = $pdo->prepare("
            UPDATE commande 
            SET statut_magasin = 'livrée',
                date_sortie = CURDATE(),
                notes = CONCAT(COALESCE(notes, ''), '\n\nملاحظات التسليم: ', :notes),
                updated_at = NOW()
            WHERE id_commande = :order_id
        ]);
        
        $updateStmt->execute([
            ':notes' => $deliveryNotes,
            ':order_id' => $orderId
        ]);
        
        $pdo->commit();
        
        // تسجيل النشاط
        logOrderActivity($pdo, 'ORDER_DELIVERED', $orderId, [
            'delivery_notes' => $deliveryNotes
        ]);
        
        echo json_encode([
            'success' => true,
            'message' => 'تم تسليم الطلب بنجاح'
        ], JSON_UNESCAPED_UNICODE);
        
    } catch (Exception $e) {
        $pdo->rollBack();
        throw new Exception('فشل في تسليم الطلب: ' . $e->getMessage());
    }
}

/**
 * إحصائيات الطلبات
 */
function getOrderStatistics(PDO $pdo): void {
    $userRole = $_SESSION['user_role'];
    $matricule = $_SESSION['user_matricule'];
    
    $statistics = [
        'total' => 0,
        'pending' => 0,
        'approved' => 0,
        'rejected' => 0,
        'delivered' => 0,
        'cancelled' => 0,
        'by_service' => [],
        'by_month' => [],
        'recent_activity' => []
    ];
    
    // شرط الصلاحيات
    $userCondition = "";
    $params = [];
    
    if ($userRole !== 'admin' && $userRole !== 'magasinier') {
        $userCondition = " AND e.matricule = :matricule";
        $params[':matricule'] = $matricule;
    }
    
    // الإحصائيات الأساسية
    $statsQuery = "
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN c.statut_service = 'en attente' THEN 1 ELSE 0 END) as pending,
            SUM(CASE WHEN c.statut_service = 'validée' THEN 1 ELSE 0 END) as approved,
            SUM(CASE WHEN c.statut_service = 'refusée' THEN 1 ELSE 0 END) as rejected,
            SUM(CASE WHEN c.statut_magasin = 'livrée' THEN 1 ELSE 0 END) as delivered,
            SUM(CASE WHEN c.statut_service = 'annulée' THEN 1 ELSE 0 END) as cancelled
        FROM commande c
        LEFT JOIN employee e ON c.employee_id = e.id
        WHERE 1=1 {$userCondition}
    ";
    
    $statsStmt = $pdo->prepare($statsQuery);
    $statsStmt->execute($params);
    $basicStats = $statsStmt->fetch(PDO::FETCH_ASSOC);
    
    if ($basicStats) {
        $statistics['total'] = (int)$basicStats['total'];
        $statistics['pending'] = (int)$basicStats['pending'];
        $statistics['approved'] = (int)$basicStats['approved'];
        $statistics['rejected'] = (int)$basicStats['rejected'];
        $statistics['delivered'] = (int)$basicStats['delivered'];
        $statistics['cancelled'] = (int)$basicStats['cancelled'];
    }
    
    // الطلبات حسب الخدمة
    $serviceQuery = "
        SELECT 
            s.design_ser as service_name,
            COUNT(c.id_commande) as order_count
        FROM commande c
        LEFT JOIN service s ON c.service_id = s.id_service
        LEFT JOIN employee e ON c.employee_id = e.id
        WHERE 1=1 {$userCondition}
        GROUP BY s.id_service, s.design_ser
        ORDER BY order_count DESC
        LIMIT 10
    ";
    
    $serviceStmt = $pdo->prepare($serviceQuery);
    $serviceStmt->execute($params);
    $statistics['by_service'] = $serviceStmt->fetchAll(PDO::FETCH_ASSOC);
    
    // الطلبات حسب الشهر (آخر 6 أشهر)
    $monthQuery = "
        SELECT 
            DATE_FORMAT(c.date_com, '%Y-%m') as month,
            COUNT(*) as order_count,
            SUM(CASE WHEN c.statut_magasin = 'livrée' THEN 1 ELSE 0 END) as delivered_count
        FROM commande c
        LEFT JOIN employee e ON c.employee_id = e.id
        WHERE c.date_com >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH)
        {$userCondition}
        GROUP BY DATE_FORMAT(c.date_com, '%Y-%m')
        ORDER BY month DESC
    ";
    
    $monthStmt = $pdo->prepare($monthQuery);
    $monthStmt->execute($params);
    $statistics['by_month'] = $monthStmt->fetchAll(PDO::FETCH_ASSOC);
    
    // النشاط الأخير
    $activityQuery = "
        SELECT 
            c.id_commande,
            c.num_commande,
            s.design_ser as service_name,
            c.statut_service,
            c.statut_magasin,
            DATE_FORMAT(c.updated_at, '%d/%m/%Y %H:%i') as last_update,
            CASE 
                WHEN c.statut_magasin = 'livrée' THEN 'تم التسليم'
                WHEN c.statut_service = 'validée' THEN 'تم الاعتماد'
                WHEN c.statut_service = 'en attente' THEN 'قيد الانتظار'
                ELSE 'محدث'
            END as status_text
        FROM commande c
        LEFT JOIN service s ON c.service_id = s.id_service
        LEFT JOIN employee e ON c.employee_id = e.id
        WHERE 1=1 {$userCondition}
        ORDER BY c.updated_at DESC
        LIMIT 10
    ";
    
    $activityStmt = $pdo->prepare($activityQuery);
    $activityStmt->execute($params);
    $statistics['recent_activity'] = $activityStmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo json_encode([
        'success' => true,
        'data' => $statistics
    ], JSON_UNESCAPED_UNICODE);
}
?>
<?php
$pageTitle = "إدارة الطلبات";
require_once 'includes/header.php';
checkLogin();
?>

<div class="container">
    <h1>إدارة الطلبات</h1>
    
    <div class="orders-container">
        <!-- هنا محتوى إدارة الطلبات -->
        <?php
        $stmt = $pdo->prepare("
            SELECT c.*, e.nom, e.prenom, s.design_ser 
            FROM commande c
            JOIN employee e ON c.employee_id = e.id
            JOIN service s ON c.service_id = s.id_service
            WHERE c.employee_id = ?
            ORDER BY c.date_com DESC
        ");
        $stmt->execute([$_SESSION['user_id']]);
        $orders = $stmt->fetchAll();
        ?>
        
        <table class="orders-table">
            <thead>
                <tr>
                    <th>رقم الطلب</th>
                    <th>التاريخ</th>
                    <th>الحالة</th>
                    <th>الإجراءات</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($orders as $order): ?>
                <tr>
                    <td><?php echo $order['num_commande']; ?></td>
                    <td><?php echo $order['date_com']; ?></td>
                    <td>
                        <span class="status status-<?php echo $order['statut_service']; ?>">
                            <?php echo $order['statut_service']; ?>
                        </span>
                    </td>
                    <td>
                        <a href="view_order.php?id=<?php echo $order['id_commande']; ?>" class="btn-view">عرض</a>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        
        <a href="create_order.php" class="btn-new-order">إنشاء طلب جديد</a>
    </div>
</div>

<?php require_once 'includes/footer.php'; ?>