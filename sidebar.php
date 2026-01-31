<?php if (isset($_SESSION['role'])): ?>
<nav class="sidebar">
    <ul>
        <li><a href="dashboard.php"><i class="icon-home"></i> الرئيسية</a></li>
        
        <?php if ($_SESSION['role'] == 'employe' || $_SESSION['role'] == 'admin'): ?>
            <li><a href="order.php"><i class="icon-order"></i> الطلبات</a></li>
        <?php endif; ?>
        
        <?php if ($_SESSION['role'] == 'magasinier' || $_SESSION['role'] == 'admin'): ?>
            <li><a href="inventory.php"><i class="icon-inventory"></i> المخزون</a></li>
        <?php endif; ?>
        
        <?php if ($_SESSION['role'] == 'admin'): ?>
            <li><a href="reports.php"><i class="icon-reports"></i> التقارير</a></li>
            <li><a href="users.php"><i class="icon-users"></i> المستخدمين</a></li>
        <?php endif; ?>
    </ul>
</nav>
<?php endif; ?>