<?php
// app_com/index.php
session_start();
require_once 'config/database.php';

$title = "نظام إدارة المخزون - الاختبار";
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $title; ?></title>
    <!-- Bootstrap 5 CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
        }
        .card {
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }
        .card:hover {
            transform: translateY(-5px);
        }
        .stat-card {
            border-left: 5px solid;
        }
        .bg-custom-1 { background: linear-gradient(45deg, #3498db, #2980b9); }
        .bg-custom-2 { background: linear-gradient(45deg, #2ecc71, #27ae60); }
        .bg-custom-3 { background: linear-gradient(45deg, #e74c3c, #c0392b); }
        .bg-custom-4 { background: linear-gradient(45deg, #9b59b6, #8e44ad); }
        .sidebar {
            background: #2c3e50;
            min-height: 100vh;
            color: white;
        }
        .sidebar .nav-link {
            color: #ecf0f1;
            padding: 15px 20px;
            border-left: 3px solid transparent;
            transition: all 0.3s;
        }
        .sidebar .nav-link:hover, .sidebar .nav-link.active {
            background: rgba(255,255,255,0.1);
            border-left: 3px solid #3498db;
            color: white;
        }
        .sidebar .logo {
            padding: 20px;
            text-align: center;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        .table-hover tbody tr:hover {
            background-color: rgba(52, 152, 219, 0.1);
        }
        .btn-custom {
            background: linear-gradient(45deg, #3498db, #2980b9);
            color: white;
            border: none;
            padding: 10px 25px;
            border-radius: 25px;
            transition: all 0.3s;
        }
        .btn-custom:hover {
            background: linear-gradient(45deg, #2980b9, #3498db);
            transform: scale(1.05);
            color: white;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <nav class="col-md-3 col-lg-2 d-md-block sidebar collapse">
                <div class="logo">
                    <h3><i class="fas fa-warehouse"></i> نظام المخزون</h3>
                    <p class="text-muted">إصدار 2.0</p>
                </div>
                <div class="position-sticky pt-3">
                    <ul class="nav flex-column">
                        <li class="nav-item">
                            <a class="nav-link active" href="#">
                                <i class="fas fa-home me-2"></i>الرئيسية
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#articles">
                                <i class="fas fa-boxes me-2"></i>المواد المخزنة
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#employees">
                                <i class="fas fa-users me-2"></i>الموظفون
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#orders">
                                <i class="fas fa-clipboard-list me-2"></i>الطلبيات
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#stats">
                                <i class="fas fa-chart-bar me-2"></i>الإحصائيات
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#test">
                                <i class="fas fa-vial me-2"></i>اختبار الاتصال
                            </a>
                        </li>
                    </ul>
                    
                    <div class="mt-5 p-3 bg-dark rounded">
                        <h6>معلومات النظام</h6>
                        <small class="text-muted">
                            <i class="fas fa-database me-1"></i> قاعدة البيانات: app_com
                        </small><br>
                        <small class="text-muted">
                            <i class="fas fa-server me-1"></i> PHP: <?php echo phpversion(); ?>
                        </small>
                    </div>
                </div>
            </nav>

            <!-- Main Content -->
            <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4 py-4">
                <!-- Header -->
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2"><i class="fas fa-tachometer-alt me-2"></i>لوحة التحكم</h1>
                    <div class="btn-toolbar mb-2 mb-md-0">
                        <div class="btn-group me-2">
                            <button type="button" class="btn btn-sm btn-outline-secondary">
                                <i class="fas fa-sync-alt"></i> تحديث
                            </button>
                            <button type="button" class="btn btn-sm btn-outline-secondary">
                                <i class="fas fa-download"></i> تصدير
                            </button>
                        </div>
                        <button type="button" class="btn btn-custom">
                            <i class="fas fa-plus-circle"></i> طلبية جديدة
                        </button>
                    </div>
                </div>

                <!-- Statistics Cards -->
                <div class="row mb-4">
                    <div class="col-xl-3 col-md-6 mb-4">
                        <div class="card border-left-primary shadow h-100 py-2 stat-card" style="border-left-color: #3498db !important;">
                            <div class="card-body">
                                <div class="row no-gutters align-items-center">
                                    <div class="col mr-2">
                                        <div class="text-xs font-weight-bold text-primary text-uppercase mb-1">
                                            المواد المخزنة</div>
                                        <div class="h5 mb-0 font-weight-bold text-gray-800">
                                            <?php
                                            $db = new Database();
                                            $total_articles = $db->query("SELECT COUNT(*) as total FROM article WHERE est_actif = 1")->fetch();
                                            echo $total_articles['total'] ?? 0;
                                            ?>
                                        </div>
                                        <div class="mt-2 mb-0 text-muted text-xs">
                                            <span class="text-success mr-2">
                                                <i class="fas fa-arrow-up"></i> 12%
                                            </span>
                                            <span>منذ الشهر الماضي</span>
                                        </div>
                                    </div>
                                    <div class="col-auto">
                                        <i class="fas fa-boxes fa-2x text-gray-300"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="col-xl-3 col-md-6 mb-4">
                        <div class="card border-left-success shadow h-100 py-2 stat-card" style="border-left-color: #2ecc71 !important;">
                            <div class="card-body">
                                <div class="row no-gutters align-items-center">
                                    <div class="col mr-2">
                                        <div class="text-xs font-weight-bold text-success text-uppercase mb-1">
                                            الطلبيات النشطة</div>
                                        <div class="h5 mb-0 font-weight-bold text-gray-800">
                                            <?php
                                            $active_orders = $db->query("SELECT COUNT(*) as total FROM commande WHERE statut_magasin IN ('en attente', 'en préparation')")->fetch();
                                            echo $active_orders['total'] ?? 0;
                                            ?>
                                        </div>
                                        <div class="mt-2 mb-0 text-muted text-xs">
                                            <span class="text-success mr-2">
                                                <i class="fas fa-clock"></i> تحت المعالجة
                                            </span>
                                        </div>
                                    </div>
                                    <div class="col-auto">
                                        <i class="fas fa-clipboard-list fa-2x text-gray-300"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="col-xl-3 col-md-6 mb-4">
                        <div class="card border-left-warning shadow h-100 py-2 stat-card" style="border-left-color: #f39c12 !important;">
                            <div class="card-body">
                                <div class="row no-gutters align-items-center">
                                    <div class="col mr-2">
                                        <div class="text-xs font-weight-bold text-warning text-uppercase mb-1">
                                            منخفضة المخزون</div>
                                        <div class="h5 mb-0 font-weight-bold text-gray-800">
                                            <?php
                                            $low_stock = $db->query("SELECT COUNT(*) as total FROM article WHERE qte_disponible <= stock_min AND est_actif = 1")->fetch();
                                            echo $low_stock['total'] ?? 0;
                                            ?>
                                        </div>
                                        <div class="mt-2 mb-0 text-muted text-xs">
                                            <span class="text-danger mr-2">
                                                <i class="fas fa-exclamation-triangle"></i> تحذير
                                            </span>
                                        </div>
                                    </div>
                                    <div class="col-auto">
                                        <i class="fas fa-exclamation-circle fa-2x text-gray-300"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="col-xl-3 col-md-6 mb-4">
                        <div class="card border-left-info shadow h-100 py-2 stat-card" style="border-left-color: #9b59b6 !important;">
                            <div class="card-body">
                                <div class="row no-gutters align-items-center">
                                    <div class="col mr-2">
                                        <div class="text-xs font-weight-bold text-info text-uppercase mb-1">
                                            إجمالي الموظفين</div>
                                        <div class="h5 mb-0 font-weight-bold text-gray-800">
                                            <?php
                                            $total_employees = $db->query("SELECT COUNT(*) as total FROM employee WHERE is_active = 1")->fetch();
                                            echo $total_employees['total'] ?? 0;
                                            ?>
                                        </div>
                                        <div class="mt-2 mb-0 text-muted text-xs">
                                            <span class="text-success mr-2">
                                                <i class="fas fa-user-check"></i> نشطون
                                            </span>
                                        </div>
                                    </div>
                                    <div class="col-auto">
                                        <i class="fas fa-users fa-2x text-gray-300"></i>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Articles Section -->
                <div id="articles" class="row mb-4">
                    <div class="col-12">
                        <div class="card shadow">
                            <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
                                <h5 class="mb-0"><i class="fas fa-boxes me-2"></i>المواد المخزنة</h5>
                                <a href="articles.php" class="btn btn-light btn-sm">عرض الكل <i class="fas fa-arrow-left"></i></a>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-hover table-striped">
                                        <thead class="table-dark">
                                            <tr>
                                                <th>الكود</th>
                                                <th>الوصف</th>
                                                <th>الفئة</th>
                                                <th>المخزون</th>
                                                <th>الحد الأدنى</th>
                                                <th>الحالة</th>
                                                <th>الإجراءات</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php
                                            $articles = $db->query("
                                                SELECT a.*, c.nom_categorie 
                                                FROM article a 
                                                LEFT JOIN categorie c ON a.categorie_id = c.id_categorie 
                                                WHERE a.est_actif = 1 
                                                ORDER BY a.qte_disponible ASC 
                                                LIMIT 10
                                            ")->fetchAll();
                                            
                                            foreach ($articles as $article):
                                                $stock_status = '';
                                                $status_color = '';
                                                
                                                if ($article['qte_disponible'] <= 0) {
                                                    $stock_status = 'نفذ';
                                                    $status_color = 'danger';
                                                } elseif ($article['qte_disponible'] <= $article['stock_min']) {
                                                    $stock_status = 'منخفض';
                                                    $status_color = 'warning';
                                                } else {
                                                    $stock_status = 'جيد';
                                                    $status_color = 'success';
                                                }
                                            ?>
                                            <tr>
                                                <td><strong><?php echo htmlspecialchars($article['code_article']); ?></strong></td>
                                                <td><?php echo htmlspecialchars($article['design_art']); ?></td>
                                                <td><?php echo htmlspecialchars($article['nom_categorie'] ?? 'غير مصنف'); ?></td>
                                                <td>
                                                    <span class="badge bg-info"><?php echo $article['qte_stock']; ?></span>
                                                    <small class="text-muted">(متاح: <?php echo $article['qte_disponible']; ?>)</small>
                                                </td>
                                                <td><?php echo $article['stock_min']; ?></td>
                                                <td>
                                                    <span class="badge bg-<?php echo $status_color; ?>">
                                                        <?php echo $stock_status; ?>
                                                    </span>
                                                </td>
                                                <td>
                                                    <button class="btn btn-sm btn-outline-primary" title="تعديل">
                                                        <i class="fas fa-edit"></i>
                                                    </button>
                                                    <button class="btn btn-sm btn-outline-info" title="التفاصيل">
                                                        <i class="fas fa-eye"></i>
                                                    </button>
                                                </td>
                                            </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Test Connection Section -->
                <div id="test" class="row mb-4">
                    <div class="col-12">
                        <div class="card shadow">
                            <div class="card-header bg-dark text-white">
                                <h5 class="mb-0"><i class="fas fa-vial me-2"></i>اختبار الاتصال بالنظام</h5>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6">
                                        <div class="card mb-3">
                                            <div class="card-header bg-info text-white">
                                                <h6 class="mb-0">اختبار قاعدة البيانات</h6>
                                            </div>
                                            <div class="card-body">
                                                <?php
                                                try {
                                                    $test = $db->query("SELECT 1");
                                                    echo '<div class="alert alert-success">';
                                                    echo '<i class="fas fa-check-circle me-2"></i>';
                                                    echo 'الاتصال بقاعدة البيانات ناجح!';
                                                    echo '</div>';
                                                    
                                                    // عرض إحصائيات
                                                    $stats = $db->query("
                                                        SELECT 
                                                            (SELECT COUNT(*) FROM article) as total_articles,
                                                            (SELECT COUNT(*) FROM employee) as total_employees,
                                                            (SELECT COUNT(*) FROM commande) as total_orders,
                                                            (SELECT COUNT(*) FROM service) as total_services
                                                    ")->fetch();
                                                } catch (Exception $e) {
                                                    echo '<div class="alert alert-danger">';
                                                    echo '<i class="fas fa-times-circle me-2"></i>';
                                                    echo 'فشل الاتصال بقاعدة البيانات: ' . $e->getMessage();
                                                    echo '</div>';
                                                    $stats = [];
                                                }
                                                ?>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <div class="col-md-6">
                                        <div class="card mb-3">
                                            <div class="card-header bg-success text-white">
                                                <h6 class="mb-0">إحصائيات النظام</h6>
                                            </div>
                                            <div class="card-body">
                                                <?php if (!empty($stats)): ?>
                                                <ul class="list-group list-group-flush">
                                                    <li class="list-group-item d-flex justify-content-between align-items-center">
                                                        المواد
                                                        <span class="badge bg-primary rounded-pill"><?php echo $stats['total_articles']; ?></span>
                                                    </li>
                                                    <li class="list-group-item d-flex justify-content-between align-items-center">
                                                        الموظفون
                                                        <span class="badge bg-success rounded-pill"><?php echo $stats['total_employees']; ?></span>
                                                    </li>
                                                    <li class="list-group-item d-flex justify-content-between align-items-center">
                                                        الطلبيات
                                                        <span class="badge bg-warning rounded-pill"><?php echo $stats['total_orders']; ?></span>
                                                    </li>
                                                    <li class="list-group-item d-flex justify-content-between align-items-center">
                                                        الخدمات
                                                        <span class="badge bg-info rounded-pill"><?php echo $stats['total_services']; ?></span>
                                                    </li>
                                                </ul>
                                                <?php endif; ?>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                
                                <!-- Test Buttons -->
                                <div class="row mt-3">
                                    <div class="col-12">
                                        <div class="d-grid gap-2 d-md-flex justify-content-md-center">
                                            <button class="btn btn-custom me-2" onclick="testTriggers()">
                                                <i class="fas fa-bolt me-2"></i>اختبار المشغلات
                                            </button>
                                            <button class="btn btn-outline-success me-2" onclick="testProcedures()">
                                                <i class="fas fa-database me-2"></i>اختبار الإجراءات
                                            </button>
                                            <button class="btn btn-outline-info" onclick="generateSampleData()">
                                                <i class="fas fa-magic me-2"></i>بيانات تجريبية
                                            </button>
                                        </div>
                                    </div>
                                </div>
                                
                                <!-- Results -->
                                <div id="testResults" class="mt-3"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>

    <!-- Footer -->
    <footer class="footer mt-auto py-3 bg-dark text-white">
        <div class="container text-center">
            <span>© 2024 نظام إدارة المخزون | الإصدار 2.0 | تم التطوير بواسطة فريق العمل</span>
            <div class="mt-2">
                <small class="text-muted">
                    PHP: <?php echo phpversion(); ?> | 
                    وقت التحميل: <?php echo round(microtime(true) - $_SERVER['REQUEST_TIME_FLOAT'], 3); ?> ثانية
                </small>
            </div>
        </div>
    </footer>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <!-- jQuery -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    
    <script>
    function testTriggers() {
        $('#testResults').html(`
            <div class="alert alert-info">
                <i class="fas fa-spinner fa-spin me-2"></i>جاري اختبار المشغلات...
            </div>
        `);
        
        $.ajax({
            url: 'test_triggers.php',
            method: 'GET',
            success: function(response) {
                $('#testResults').html(response);
            },
            error: function() {
                $('#testResults').html(`
                    <div class="alert alert-danger">
                        <i class="fas fa-times-circle me-2"></i>فشل في اختبار المشغلات
                    </div>
                `);
            }
        });
    }
    
    function testProcedures() {
        $('#testResults').html(`
            <div class="alert alert-info">
                <i class="fas fa-spinner fa-spin me-2"></i>جاري اختبار الإجراءات المخزنة...
            </div>
        `);
        
        $.ajax({
            url: 'test_procedures.php',
            method: 'GET',
            success: function(response) {
                $('#testResults').html(response);
            },
            error: function() {
                $('#testResults').html(`
                    <div class="alert alert-danger">
                        <i class="fas fa-times-circle me-2"></i>فشل في اختبار الإجراءات
                    </div>
                `);
            }
        });
    }
    
    function generateSampleData() {
        if (confirm('هل تريد إنشاء بيانات تجريبية؟ هذا سيضيف سجلات جديدة.')) {
            $('#testResults').html(`
                <div class="alert alert-info">
                    <i class="fas fa-spinner fa-spin me-2"></i>جاري إنشاء البيانات التجريبية...
                </div>
            `);
            
            $.ajax({
                url: 'generate_sample.php',
                method: 'GET',
                success: function(response) {
                    $('#testResults').html(response);
                    setTimeout(() => location.reload(), 2000);
                },
                error: function() {
                    $('#testResults').html(`
                        <div class="alert alert-danger">
                            <i class="fas fa-times-circle me-2"></i>فشل في إنشاء البيانات التجريبية
                        </div>
                    `);
                }
            });
        }
    }
    
    // Auto-refresh stock alerts every 30 seconds
    setInterval(function() {
        $.ajax({
            url: 'check_alerts.php',
            method: 'GET',
            success: function(response) {
                if (response.alerts > 0) {
                    $('.low-stock-count').text(response.alerts);
                }
            }
        });
    }, 30000);
    </script>
</body>
</html>