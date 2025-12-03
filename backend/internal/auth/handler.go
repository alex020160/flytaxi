package auth

import (
    "context"
    "net/http"
    "strings"
    "crypto/rand"
    "fmt"
    "log"
    "math/big"
    "net/smtp"
    "os"
    "time"
    "strconv"

    "github.com/gin-gonic/gin"
    "github.com/jackc/pgx/v5/pgxpool"
    "golang.org/x/crypto/bcrypt"
)

const (
    adminLoginConst    = "admin06042006"
    adminPasswordConst = "super_admin_taxi"
)

func (h *Handler) AdminLogin(c *gin.Context) {
    var req struct {
        Login    string `json:"login" binding:"required"`
        Password string `json:"password" binding:"required"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Проверьте введённые данные"})
        return
    }

    if req.Login != adminLoginConst || req.Password != adminPasswordConst {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверный логин или пароль"})
        return
    }

    // Здесь пока без JWT/сессий — просто подтверждаем успешный вход.
    c.JSON(http.StatusOK, gin.H{
        "message": "Добро пожаловать, администратор!",
    })
}


type Handler struct {
    db  *pgxpool.Pool
    jwt *JWTManager
}

func NewHandler(db *pgxpool.Pool, jwt *JWTManager) *Handler {
    return &Handler{
        db:  db,
        jwt: jwt,
    }
}

/* ==================== CLIENT REGISTER ==================== */

type registerClientRequest struct {
    FirstName  string `json:"first_name" binding:"required"`
    LastName   string `json:"last_name" binding:"required"`
    MiddleName string `json:"middle_name"`
    Email      string `json:"email" binding:"required,email"`
    Phone      string `json:"phone" binding:"required"`
    Password   string `json:"password" binding:"required,min=6"`
}



type pendingDriverResponse struct {
    DriverID        int64  `json:"driver_id"`
    UserID          int64  `json:"user_id"`
    FirstName       string `json:"first_name"`
    LastName        string `json:"last_name"`
    MiddleName      string `json:"middle_name"`
    Email           string `json:"email"`
    Phone           string `json:"phone"`
    CarMake         string `json:"car_make"`
    CarModel        string `json:"car_model"`
    CarColor        string `json:"car_color"`
    CarPlateNumber  string `json:"car_plate_number"`
    DriverLicense   string `json:"driver_license_num"`
    LicenseExpires  string `json:"license_expires_at"`
    ExperienceYears int    `json:"experience_years"`
}


func (h *Handler) RegisterClient(c *gin.Context) {
    var req registerClientRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        // грубая, но понятная обработка
        if strings.Contains(err.Error(), "Password") && strings.Contains(err.Error(), "min") {
            c.JSON(http.StatusBadRequest, gin.H{"error": "Пароль должен быть не короче 6 символов"})
            return
        }

        c.JSON(http.StatusBadRequest, gin.H{"error": "Проверьте правильность введённых данных"})
        return
    }

    hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
        return
    }

    query := `
        INSERT INTO users (role, first_name, last_name, middle_name, email, phone, password_hash)
        VALUES ('client', $1, $2, $3, $4, $5, $6)
        RETURNING id
    `
    var id int64
    err = h.db.QueryRow(context.Background(), query,
        req.FirstName,
        req.LastName,
        req.MiddleName,
        strings.ToLower(req.Email),
        req.Phone,
        string(hash),
    ).Scan(&id)

    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
        return
    }

    token, err := h.jwt.Generate(id, "client")
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
        return
    }

    c.JSON(http.StatusCreated, gin.H{
        "access_token": token,
        "user": gin.H{
            "id":         id,
            "role":       "client",
            "first_name": req.FirstName,
            "last_name":  req.LastName,
        },
    })
}

/* ==================== DRIVER REGISTER ==================== */

type registerDriverRequest struct {
    FirstName        string `json:"first_name" binding:"required"`
    LastName         string `json:"last_name" binding:"required"`
    MiddleName       string `json:"middle_name"`
    Email            string `json:"email" binding:"required,email"`
    Phone            string `json:"phone" binding:"required"`
    Password         string `json:"password" binding:"required,min=6"`

    CarMake          string `json:"car_make" binding:"required"`
    CarModel         string `json:"car_model" binding:"required"`
    CarColor         string `json:"car_color" binding:"required"`
    CarPlateNumber   string `json:"car_plate_number" binding:"required"`
    DriverLicenseNum string `json:"driver_license_num" binding:"required"`
    LicenseExpiresAt string `json:"license_expires_at" binding:"required"` // строка, парсим сами
    ExperienceYears  int    `json:"experience_years" binding:"required"`
}


func (h *Handler) RegisterDriver(c *gin.Context) {
    var req registerDriverRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        log.Printf("RegisterDriver bind error: %v", err)
        c.JSON(http.StatusBadRequest, gin.H{"error": "Проверьте правильность введённых данных"})
        return
    }

    // Парсим дату в формате, который отдаёт <input type="date">: 2006-01-02
    licenseDate, err := time.Parse("2006-01-02", req.LicenseExpiresAt)
    if err != nil {
        log.Printf("RegisterDriver license parse error: %v, value=%s", err, req.LicenseExpiresAt)
        c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат даты действия прав"})
        return
    }

    // Хэшируем пароль
    hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    if err != nil {
        log.Printf("RegisterDriver bcrypt error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сервера (хэш пароля)"})
        return
    }

    ctx := context.Background()
    tx, err := h.db.Begin(ctx)
    if err != nil {
        log.Printf("RegisterDriver begin tx error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сервера (транзакция)"})
        return
    }
    defer tx.Rollback(ctx)

    // 1. создаём пользователя
    var userID int64
    err = tx.QueryRow(ctx, `
        INSERT INTO users (role, first_name, last_name, middle_name, email, phone, password_hash, is_active)
        VALUES ('driver', $1, $2, $3, $4, $5, $6, TRUE)
        RETURNING id
    `,
        req.FirstName,
        req.LastName,
        req.MiddleName,
        req.Email,
        req.Phone,
        string(hash),
    ).Scan(&userID)

    if err != nil {
        log.Printf("RegisterDriver insert user error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать пользователя (возможно, email или телефон уже заняты)"})
        return
    }

    // 2. создаём запись водителя
    _, err = tx.Exec(ctx, `
        INSERT INTO drivers (
            user_id,
            car_make,
            car_model,
            car_color,
            car_plate_number,
            driver_license_num,
            license_expires_at,
            experience_years,
            is_approved
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,FALSE)
    `,
        userID,
        req.CarMake,
        req.CarModel,
        req.CarColor,
        req.CarPlateNumber,
        req.DriverLicenseNum,
        licenseDate,
        req.ExperienceYears,
    )
    if err != nil {
        log.Printf("RegisterDriver insert driver error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось сохранить данные водителя"})
        return
    }

    if err := tx.Commit(ctx); err != nil {
        log.Printf("RegisterDriver commit error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сервера (commit)"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "message": "Регистрация отправлена! После подтверждения вы сможете войти.",
    })
}

/* ==================== LOGIN (client + driver) ==================== */

type loginRequest struct {
    Identifier string `json:"identifier" binding:"required"` // телефон ИЛИ email
    Password   string `json:"password" binding:"required"`
}

func (h *Handler) Login(c *gin.Context) {
    var req loginRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    identifier := strings.ToLower(strings.TrimSpace(req.Identifier))

    // ищем по телефону или email
    query := `
        SELECT id, role, first_name, last_name, password_hash
        FROM users
        WHERE phone = $1 OR lower(email) = $1
        LIMIT 1
    `
    var (
        id           int64
        role         string
        firstName    string
        lastName     string
        passwordHash string
    )

    err := h.db.QueryRow(context.Background(), query, identifier).
        Scan(&id, &role, &firstName, &lastName, &passwordHash)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
        return
    }

    if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
        return
    }

    token, err := h.jwt.Generate(id, role)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "access_token": token,
        "user": gin.H{
            "id":         id,
            "role":       role,
            "first_name": firstName,
            "last_name":  lastName,
        },
    })
}

func generateResetCode() (string, error) {
    // 6-значный код, например 483920
    n, err := rand.Int(rand.Reader, big.NewInt(1000000))
    if err != nil {
        return "", err
    }
    return fmt.Sprintf("%06d", n.Int64()), nil
}

func sendResetEmail(toEmail, code string) {
    host := os.Getenv("SMTP_HOST")
    port := os.Getenv("SMTP_PORT")
    user := os.Getenv("SMTP_USERNAME")
    pass := os.Getenv("SMTP_PASSWORD")
    from := os.Getenv("SMTP_FROM")

    if host == "" || port == "" || user == "" || pass == "" || from == "" {
        log.Printf("[RESET EMAIL] SMTP env not fully set, email=%s code=%s", toEmail, code)
        return
    }

    addr := host + ":" + port

    subject := "Код восстановления пароля FlyTaxi"
    body := fmt.Sprintf(
        "Здравствуйте!\n\nВаш код для восстановления пароля: %s\nОн действует 15 минут.\n\nЕсли вы не запрашивали сброс пароля, просто игнорируйте это письмо.\n\nС уважением,\nКоманда FlyTaxi",
        code,
    )

    msg := "From: " + from + "\r\n" +
        "To: " + toEmail + "\r\n" +
        "Subject: " + subject + "\r\n" +
        "MIME-Version: 1.0\r\n" +
        "Content-Type: text/plain; charset=\"utf-8\"\r\n" +
        "\r\n" + body

    auth := smtp.PlainAuth("", user, pass, host)

    if err := smtp.SendMail(addr, auth, from, []string{toEmail}, []byte(msg)); err != nil {
        log.Printf("sendResetEmail error: %v", err)
    } else {
        log.Printf("Password reset email sent to %s", toEmail)
    }
}

func (h *Handler) ForgotPassword(c *gin.Context) {
    var req struct {
        Identifier string `json:"identifier" binding:"required"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Некорректные данные"})
        return
    }

    identifier := strings.TrimSpace(strings.ToLower(req.Identifier))

    var (
        userID int64
        email  string
    )

    query := `
        SELECT id, email
        FROM users
        WHERE phone = $1 OR lower(email) = $1
        LIMIT 1
    `
    err := h.db.QueryRow(context.Background(), query, identifier).Scan(&userID, &email)
    if err != nil || email == "" {
        log.Printf("ForgotPassword: user not found for identifier=%s: %v", identifier, err)
        // Наружу всегда говорим одно и то же
        c.JSON(http.StatusOK, gin.H{
            "message": "Если такой пользователь существует, на его email отправлено письмо с кодом.",
        })
        return
    }

    // Генерируем код
    code, err := generateResetCode()
    if err != nil {
        log.Printf("generateResetCode error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать код восстановления"})
        return
    }

    // Сохраняем в БД
    _, err = h.db.Exec(context.Background(), `
        INSERT INTO password_reset_tokens (user_id, code, expires_at)
        VALUES ($1, $2, NOW() + INTERVAL '15 minutes')
    `, userID, code)
    if err != nil {
        log.Printf("insert password_reset_tokens error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось сохранить код восстановления"})
        return
    }

    // Отправляем письмо
    sendResetEmail(email, code)

    c.JSON(http.StatusOK, gin.H{
        "message": "Если такой пользователь существует, на его email отправлено письмо с кодом.",
    })
}


func (h *Handler) ResetPassword(c *gin.Context) {
    var req struct {
        Email       string `json:"email" binding:"required,email"`
        Code        string `json:"code" binding:"required"`
        NewPassword string `json:"new_password" binding:"required,min=6"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Проверьте введённые данные"})
        return
    }

    email := strings.ToLower(strings.TrimSpace(req.Email))
    code := strings.TrimSpace(req.Code)

    var (
        tokenID int64
        userID  int64
    )

    query := `
        SELECT t.id, t.user_id
        FROM password_reset_tokens t
        JOIN users u ON u.id = t.user_id
        WHERE lower(u.email) = $1
          AND t.code = $2
          AND t.expires_at > NOW()
          AND t.used_at IS NULL
        ORDER BY t.created_at DESC
        LIMIT 1
    `
    err := h.db.QueryRow(context.Background(), query, email, code).Scan(&tokenID, &userID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный или просроченный код"})
        return
    }

    hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось обновить пароль"})
        return
    }

    // Обновляем пароль
    _, err = h.db.Exec(context.Background(),
        `UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2`,
        string(hash), userID,
    )
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось обновить пароль"})
        return
    }

    // Помечаем токен использованным
    _, err = h.db.Exec(context.Background(),
        `UPDATE password_reset_tokens SET used_at = NOW() WHERE id = $1`,
        tokenID,
    )
    if err != nil {
        log.Printf("ResetPassword: failed to mark token used: %v", err)
    }

    c.JSON(http.StatusOK, gin.H{"message": "Пароль успешно изменён. Теперь вы можете войти."})
}

func (h *Handler) ListPendingDrivers(c *gin.Context) {
    rows, err := h.db.Query(context.Background(), `
        SELECT
            d.id,
            u.id,
            u.first_name,
            u.last_name,
            u.middle_name,
            u.email,
            u.phone,
            d.car_make,
            d.car_model,
            d.car_color,
            d.car_plate_number,
            d.driver_license_num,
            d.license_expires_at,
            d.experience_years
        FROM drivers d
        JOIN users u ON u.id = d.user_id
        WHERE d.is_approved = FALSE
        ORDER BY d.created_at DESC
    `)
    if err != nil {
        log.Printf("ListPendingDrivers query error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось получить список водителей"})
        return
    }
    defer rows.Close()

    var list []pendingDriverResponse
    for rows.Next() {
        var item pendingDriverResponse
        var license time.Time

        if err := rows.Scan(
            &item.DriverID,
            &item.UserID,
            &item.FirstName,
            &item.LastName,
            &item.MiddleName,
            &item.Email,
            &item.Phone,
            &item.CarMake,
            &item.CarModel,
            &item.CarColor,
            &item.CarPlateNumber,
            &item.DriverLicense,
            &license,
            &item.ExperienceYears,
        ); err != nil {
            log.Printf("ListPendingDrivers scan error: %v", err)
            continue
        }

        item.LicenseExpires = license.Format("2006-01-02")
        list = append(list, item)
    }

    c.JSON(http.StatusOK, gin.H{"drivers": list})
}


func (h *Handler) GetDriverApplication(c *gin.Context) {
    idStr := c.Param("id")
    driverID, err := strconv.ParseInt(idStr, 10, 64)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Некорректный ID"})
        return
    }

    var item pendingDriverResponse
    var license time.Time

    err = h.db.QueryRow(context.Background(), `
        SELECT
            d.id,
            u.id,
            u.first_name,
            u.last_name,
            u.middle_name,
            u.email,
            u.phone,
            d.car_make,
            d.car_model,
            d.car_color,
            d.car_plate_number,
            d.driver_license_num,
            d.license_expires_at,
            d.experience_years
        FROM drivers d
        JOIN users u ON u.id = d.user_id
        WHERE d.id = $1
    `, driverID).Scan(
        &item.DriverID,
        &item.UserID,
        &item.FirstName,
        &item.LastName,
        &item.MiddleName,
        &item.Email,
        &item.Phone,
        &item.CarMake,
        &item.CarModel,
        &item.CarColor,
        &item.CarPlateNumber,
        &item.DriverLicense,
        &license,
        &item.ExperienceYears,
    )

    if err != nil {
        log.Printf("GetDriverApplication error: %v", err)
        c.JSON(http.StatusNotFound, gin.H{"error": "Заявка не найдена"})
        return
    }

    item.LicenseExpires = license.Format("2006-01-02")
    c.JSON(http.StatusOK, item)
}


func (h *Handler) ApproveDriver(c *gin.Context) {
    idStr := c.Param("id")
    driverID, err := strconv.ParseInt(idStr, 10, 64)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Некорректный ID водителя"})
        return
    }

    cmd, err := h.db.Exec(context.Background(),
        `UPDATE drivers
         SET is_approved = TRUE,
             updated_at = NOW()
         WHERE id = $1`,
        driverID,
    )
    if err != nil {
        log.Printf("ApproveDriver update error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось обновить статус"})
        return
    }

    if cmd.RowsAffected() == 0 {
        c.JSON(http.StatusNotFound, gin.H{"error": "Водитель не найден"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Водитель одобрен"})
}


func (h *Handler) RejectDriver(c *gin.Context) {
    idStr := c.Param("id")
    driverID, err := strconv.ParseInt(idStr, 10, 64)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Некорректный ID водителя"})
        return
    }

    cmd, err := h.db.Exec(context.Background(),
        `UPDATE drivers
         SET is_approved = FALSE,
             updated_at = NOW()
         WHERE id = $1`,
        driverID,
    )
    if err != nil {
        log.Printf("RejectDriver update error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось обновить статус"})
        return
    }

    if cmd.RowsAffected() == 0 {
        c.JSON(http.StatusNotFound, gin.H{"error": "Водитель не найден"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Заявка отклонена"})
}




