package auth

import (
    "context"
    "crypto/rand"
    "database/sql"
    "fmt"
    "log"
    mrand "math/rand"
    "math/big"
    "net/http"
    "net/smtp"
    "os"
    "strconv"
    "strings"
    "time"

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

    token, err := h.jwt.Generate(-1, "admin")
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось выдать токен"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "access_token": token,
        "user": gin.H{
            "id":    -1,
            "role":  "admin",
            "login": req.Login,
        },
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
    LicenseExpiresAt string `json:"license_expires_at" binding:"required"`
    ExperienceYears  int    `json:"experience_years" binding:"required"`
}

func (h *Handler) RegisterDriver(c *gin.Context) {
    var req registerDriverRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        log.Printf("RegisterDriver bind error: %v", err)
        c.JSON(http.StatusBadRequest, gin.H{"error": "Проверьте правильность введённых данных"})
        return
    }

    licenseDate, err := time.Parse("2006-01-02", req.LicenseExpiresAt)
    if err != nil {
        log.Printf("RegisterDriver license parse error: %v, value=%s", err, req.LicenseExpiresAt)
        c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат даты действия прав"})
        return
    }

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
    Identifier string `json:"identifier" binding:"required"`
    Password   string `json:"password" binding:"required"`
}

func (h *Handler) Login(c *gin.Context) {
    var req loginRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    identifier := strings.ToLower(strings.TrimSpace(req.Identifier))

    query := `
        SELECT id, role, first_name, last_name, email, phone, password_hash, driver_class
        FROM users
        WHERE phone = $1 OR lower(email) = $1
        LIMIT 1
    `
    var (
        id           int64
        role         string
        firstName    string
        lastName     string
        email        string
        phone        string
        passwordHash string
        driverClass  sql.NullString
    )

    err := h.db.QueryRow(context.Background(), query, identifier).
        Scan(&id, &role, &firstName, &lastName, &email, &phone, &passwordHash, &driverClass)

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

    userResp := gin.H{
        "id":         id,
        "role":       role,
        "first_name": firstName,
        "last_name":  lastName,
        "email":      email,
        "phone":      phone,
    }

    if role == "driver" {
        if driverClass.Valid {
            userResp["driver_class"] = driverClass.String
        } else {
            userResp["driver_class"] = ""
        }
    }

    c.JSON(http.StatusOK, gin.H{
        "access_token": token,
        "user":         userResp,
    })
}

// простая функция для примерного времени и цены
func calcETAAndPrice(carClass string) (etaMinutes int, price int) {
    etaMinutes = 10 + mrand.Intn(111)

    base := 150
    switch carClass {
    case "business":
        base = 350
    case "comfort":
        base = 250
    case "kids":
        base = 220
    }

    price = base + etaMinutes*4
    return
}

func carClassToText(code string) string {
    switch code {
    case "business":
        return "Бизнес"
    case "comfort":
        return "Комфорт"
    case "kids":
        return "С детьми"
    default:
        return "Эконом"
    }
}

type createRideRequest struct {
    From        string `json:"from" binding:"required"`
    To          string `json:"to" binding:"required"`
    CarClass    string `json:"car_class" binding:"required"`
    WithPet     bool   `json:"with_pet"`
    WithBooster bool   `json:"with_booster"`
    Comment     string `json:"comment"`
    EtaMinutes  *int   `json:"eta_minutes"`
    Price       *int   `json:"price"`
}

type rideForDriverResponse struct {
    ID          int64      `json:"id"`
    From        string     `json:"from"`
    To          string     `json:"to"`
    CarClass    string     `json:"car_class_text"`
    Price       *int       `json:"price,omitempty"`
    WithPet     bool       `json:"with_pet"`
    WithBooster bool       `json:"with_booster"`
    Comment     string     `json:"comment"`
    EtaMinutes  int        `json:"eta_minutes"`
    Status      string     `json:"status"`
    StartedAt   *time.Time `json:"started_at,omitempty"`
    FinishedAt  *time.Time `json:"finished_at,omitempty"`

    Rating     *int   `json:"rating,omitempty"`
    TipAmount  *int   `json:"tip_amount,omitempty"`
    ClientNote string `json:"client_note,omitempty"`
}

func generateResetCode() (string, error) {
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
        c.JSON(http.StatusOK, gin.H{
            "message": "Если такой пользователь существует, на его email отправлено письмо с кодом.",
        })
        return
    }

    code, err := generateResetCode()
    if err != nil {
        log.Printf("generateResetCode error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать код восстановления"})
        return
    }

    _, err = h.db.Exec(context.Background(), `
        INSERT INTO password_reset_tokens (user_id, code, expires_at)
        VALUES ($1, $2, NOW() + INTERVAL '15 minutes')
    `, userID, code)
    if err != nil {
        log.Printf("insert password_reset_tokens error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось сохранить код восстановления"})
        return
    }

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

    _, err = h.db.Exec(context.Background(),
        `UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2`,
        string(hash), userID,
    )
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось обновить пароль"})
        return
    }

    _, err = h.db.Exec(context.Background(),
        `UPDATE password_reset_tokens SET used_at = NOW() WHERE id = $1`,
        tokenID,
    )
    if err != nil {
        log.Printf("ResetPassword: failed to mark token used: %v", err)
    }

    c.JSON(http.StatusOK, gin.H{"message": "Пароль успешно изменён. Теперь вы можете войти."})
}

/* ==================== CREATE RIDE (фикс: привязка к клиенту) ==================== */

// CreateRide - клиент создаёт новый заказ
func (h *Handler) CreateRide(c *gin.Context) {
    // Обязательно авторизованный клиент
    v, ok := c.Get("userID")
    if !ok {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Нужно войти в аккаунт клиента"})
        return
    }
    clientID, ok := v.(int64)
    if !ok {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка авторизации"})
        return
    }

    if roleVal, ok := c.Get("role"); ok {
        if roleStr, ok2 := roleVal.(string); ok2 && roleStr != "client" {
            c.JSON(http.StatusForbidden, gin.H{"error": "Создание заказа доступно только клиенту"})
            return
        }
    }

    var req createRideRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        log.Printf("CreateRide bind error: %v", err)
        c.JSON(http.StatusBadRequest, gin.H{"error": "Проверьте заполнение полей маршрута"})
        return
    }

    eta, price := calcETAAndPrice(req.CarClass)

    if req.EtaMinutes != nil && req.Price != nil && *req.Price > 0 {
        eta = *req.EtaMinutes
        price = *req.Price
    }

    var rideID int64
    err := h.db.QueryRow(context.Background(), `
        INSERT INTO rides (
            client_id,
            from_address,
            to_address,
            car_class,
            with_pet,
            with_booster,
            comment,
            price,
            eta_minutes,
            status
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'new')
        RETURNING id
    `,
        clientID,
        req.From,
        req.To,
        req.CarClass,
        req.WithPet,
        req.WithBooster,
        req.Comment,
        price,
        eta,
    ).Scan(&rideID)

    if err != nil {
        log.Printf("CreateRide insert error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать заказ"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "message":     "Заказ создан! Ищем свободного водителя.",
        "ride_id":     rideID,
        "eta_minutes": eta,
        "price":       price,
    })
}

/* ==================== DRIVER ORDERS ==================== */

func (h *Handler) ListAvailableOrders(c *gin.Context) {
    v, ok := c.Get("userID")
    if !ok {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Не авторизован"})
        return
    }
    driverID, ok := v.(int64)
    if !ok {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка авторизации"})
        return
    }

    ctx := context.Background()

    var driverClass sql.NullString
    if err := h.db.QueryRow(ctx, `
        SELECT driver_class
        FROM users
        WHERE id = $1
    `, driverID).Scan(&driverClass); err != nil {
        log.Printf("ListAvailableOrders get driver_class error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось получить класс автомобиля"})
        return
    }

    if !driverClass.Valid || driverClass.String == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Для вашего аккаунта не назначен класс автомобиля. Обратитесь к администратору."})
        return
    }

    rows, err := h.db.Query(ctx, `
        SELECT
            id,
            from_address,
            to_address,
            car_class,
            with_pet,
            with_booster,
            comment,
            eta_minutes,
            price,
            status,
            started_at,
            finished_at,
            rating,
            tip_amount,
            client_note
        FROM rides
        WHERE
              (status = 'new' AND car_class = $1)
           OR (driver_id = $2 AND status IN ('assigned','in_progress','finished'))
        ORDER BY created_at DESC
    `, driverClass.String, driverID)

    if err != nil {
        log.Printf("ListAvailableOrders query error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось получить заказы"})
        return
    }
    defer rows.Close()

    var list []rideForDriverResponse

    for rows.Next() {
        var (
            r            rideForDriverResponse
            carClassCode string
            eta          *int
            price        *int
            status       string
            startedAt    *time.Time
            finishedAt   *time.Time
            rating       sql.NullInt32
            tip          sql.NullInt32
            clientNote   sql.NullString
        )

        if err := rows.Scan(
            &r.ID,
            &r.From,
            &r.To,
            &carClassCode,
            &r.WithPet,
            &r.WithBooster,
            &r.Comment,
            &eta,
            &price,
            &status,
            &startedAt,
            &finishedAt,
            &rating,
            &tip,
            &clientNote,
        ); err != nil {
            log.Printf("ListAvailableOrders scan error: %v", err)
            continue
        }

        r.CarClass = carClassToText(carClassCode)
        if eta != nil {
            r.EtaMinutes = *eta
        } else {
            r.EtaMinutes, _ = calcETAAndPrice(carClassCode)
        }
        r.Price = price
        r.Status = status
        r.StartedAt = startedAt
        r.FinishedAt = finishedAt

        if rating.Valid {
            v := int(rating.Int32)
            r.Rating = &v
        }
        if tip.Valid {
            v := int(tip.Int32)
            r.TipAmount = &v
        }
        if clientNote.Valid {
            r.ClientNote = clientNote.String
        }

        list = append(list, r)
    }
    c.JSON(http.StatusOK, gin.H{"orders": list})
}

func (h *Handler) AcceptOrder(c *gin.Context) {
    idStr := c.Param("id")
    rideID, err := strconv.ParseInt(idStr, 10, 64)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Некорректный ID заказа"})
        return
    }

    v, ok := c.Get("userID")
    if !ok {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Не авторизован"})
        return
    }
    driverID, ok := v.(int64)
    if !ok {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка авторизации"})
        return
    }

    ctx := context.Background()

    var driverClass sql.NullString
    if err := h.db.QueryRow(ctx, `
        SELECT driver_class
        FROM users
        WHERE id = $1
    `, driverID).Scan(&driverClass); err != nil {
        log.Printf("AcceptOrder get driver_class error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось получить класс автомобиля"})
        return
    }

    if !driverClass.Valid || driverClass.String == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Для вашего аккаунта не назначен класс автомобиля. Обратитесь к администратору."})
        return
    }

    cmd, err := h.db.Exec(ctx, `
        UPDATE rides
        SET status    = 'assigned',
            driver_id = $2,
            updated_at = NOW()
        WHERE id        = $1
          AND status    = 'new'
          AND car_class = $3
    `, rideID, driverID, driverClass.String)
    if err != nil {
        log.Printf("AcceptOrder update error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось принять заказ"})
        return
    }

    if cmd.RowsAffected() == 0 {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Заказ уже недоступен для вашего класса автомобиля"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Заказ принят"})
}

func (h *Handler) RejectOrder(c *gin.Context) {
    idStr := c.Param("id")
    rideID, err := strconv.ParseInt(idStr, 10, 64)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Некорректный ID заказа"})
        return
    }

    cmd, err := h.db.Exec(context.Background(), `
        UPDATE rides
        SET status = 'cancelled',
            updated_at = NOW()
        WHERE id = $1 AND status = 'new'
    `, rideID)
    if err != nil {
        log.Printf("RejectOrder update error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось отменить заказ"})
        return
    }

    if cmd.RowsAffected() == 0 {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Заказ уже недоступен"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Заказ отклонён"})
}

/* ==================== ADMIN DRIVERS ==================== */

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

    var req struct {
        CarClass string `json:"driver_class" binding:"required"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Укажите класс автомобиля"})
        return
    }

    class := strings.ToLower(strings.TrimSpace(req.CarClass))
    switch class {
    case "econom", "business", "comfort", "kids":
    default:
        c.JSON(http.StatusBadRequest, gin.H{"error": "Некорректный класс (econom|business|comfort|kids)"})
        return
    }

    ctx := context.Background()

    cmd, err := h.db.Exec(ctx,
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

    _, err = h.db.Exec(ctx,
        `UPDATE users
        SET driver_class = $2
        WHERE id = (SELECT user_id FROM drivers WHERE id = $1)`,
        driverID, class,
    )
    if err != nil {
        log.Printf("ApproveDriver set driver_class error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось сохранить класс автомобиля"})
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

    ctx := context.Background()
    tx, err := h.db.Begin(ctx)
    if err != nil {
        log.Printf("RejectDriver begin tx error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сервера"})
        return
    }
    defer tx.Rollback(ctx)

    var userID int64
    if err := tx.QueryRow(ctx, `
        SELECT user_id
        FROM drivers
        WHERE id = $1
    `, driverID).Scan(&userID); err != nil {
        if err == sql.ErrNoRows {
            c.JSON(http.StatusNotFound, gin.H{"error": "Водитель не найден"})
        } else {
            log.Printf("RejectDriver select user_id error: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сервера"})
        }
        return
    }

    if _, err := tx.Exec(ctx, `
        DELETE FROM drivers
        WHERE id = $1
        AND is_approved = FALSE
    `, driverID); err != nil {
        log.Printf("RejectDriver delete driver error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось удалить водителя"})
        return
    }

    if _, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID); err != nil {
        log.Printf("RejectDriver delete user error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось удалить пользователя"})
        return
    }

    if err := tx.Commit(ctx); err != nil {
        log.Printf("RejectDriver commit error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сервера (commit)"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Заявка отклонена и данные водителя удалены"})
}

/* ==================== RIDE STATUS (start/finish/cancel/rate) ==================== */

func (h *Handler) StartRide(c *gin.Context) {
    idStr := c.Param("id")
    rideID, err := strconv.ParseInt(idStr, 10, 64)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Некорректный ID заказа"})
        return
    }

    v, ok := c.Get("userID")
    if !ok {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Не авторизован"})
        return
    }
    driverID, ok := v.(int64)
    if !ok {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка авторизации"})
        return
    }

    cmd, err := h.db.Exec(context.Background(), `
        UPDATE rides
        SET status = 'in_progress',
            started_at = NOW(),
            updated_at = NOW()
        WHERE id = $1
          AND driver_id = $2
          AND status = 'assigned'
    `, rideID, driverID)
    if err != nil {
        log.Printf("StartRide update error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось начать поездку"})
        return
    }

    if cmd.RowsAffected() == 0 {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Поездку нельзя начать (не найдена или неверный статус)"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Поездка началась"})
}

func (h *Handler) FinishRide(c *gin.Context) {
    idStr := c.Param("id")
    rideID, err := strconv.ParseInt(idStr, 10, 64)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Некорректный ID заказа"})
        return
    }

    v, ok := c.Get("userID")
    if !ok {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Не авторизован"})
        return
    }
    driverID, ok := v.(int64)
    if !ok {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка авторизации"})
        return
    }

    cmd, err := h.db.Exec(context.Background(), `
        UPDATE rides
        SET status = 'finished',
            finished_at = NOW(),
            updated_at = NOW()
        WHERE id = $1
          AND driver_id = $2
          AND status = 'in_progress'
    `, rideID, driverID)
    if err != nil {
        log.Printf("FinishRide update error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось завершить поездку"})
        return
    }

    if cmd.RowsAffected() == 0 {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Поездку нельзя завершить (не найдена или неверный статус)"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Поездка завершена"})
}

func (h *Handler) CancelRide(c *gin.Context) {
    idStr := c.Param("id")
    rideID, err := strconv.ParseInt(idStr, 10, 64)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Некорректный ID заказа"})
        return
    }

    v, ok := c.Get("userID")
    if !ok {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Не авторизован"})
        return
    }
    clientID, ok := v.(int64)
    if !ok {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка авторизации"})
        return
    }

    cmd, err := h.db.Exec(context.Background(), `
        UPDATE rides
        SET status = 'cancelled',
            cancelled_by = 'client',
            updated_at = NOW()
        WHERE id = $1
          AND client_id = $2
          AND status IN ('new','assigned')
    `, rideID, clientID)
    if err != nil {
        log.Printf("CancelRide update error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось отменить заказ"})
        return
    }

    if cmd.RowsAffected() == 0 {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Заказ нельзя отменить (не найден или уже в работе)"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Заказ отменён"})
}

func (h *Handler) RateRide(c *gin.Context) {
    idStr := c.Param("id")
    rideID, err := strconv.ParseInt(idStr, 10, 64)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Некорректный ID заказа"})
        return
    }

    v, ok := c.Get("userID")
    if !ok {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Не авторизован"})
        return
    }
    clientID, ok := v.(int64)
    if !ok {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка авторизации"})
        return
    }

    var req struct {
        Rating  int    `json:"rating"`
        Tip     int    `json:"tip_amount"`
        Comment string `json:"comment"`
    }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Некорректные данные"})
        return
    }

    if req.Rating < 0 || req.Rating > 5 {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Рейтинг от 0 до 5"})
        return
    }
    if req.Tip < 0 {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Чаевые не могут быть отрицательными"})
        return
    }

    cmd, err := h.db.Exec(context.Background(), `
        UPDATE rides
        SET rating      = $3,
            tip_amount  = $4,
            client_note = $5,
            updated_at  = NOW()
        WHERE id = $1
            AND client_id = $2
            AND status = 'finished'
    `, rideID, clientID, req.Rating, req.Tip, req.Comment)
    if err != nil {
        log.Printf("RateRide update error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось сохранить оценку"})
        return
    }

    if cmd.RowsAffected() == 0 {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Нельзя оценить этот заказ (уже оценён или неверный статус)"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Спасибо за оценку!"})
}

/* ==================== CLIENT ACTIVE RIDE (фикс: rating) ==================== */

func (h *Handler) GetClientActiveRide(c *gin.Context) {
    v, ok := c.Get("userID")
    if !ok {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Не авторизован"})
        return
    }
    clientID := v.(int64)

    var resp struct {
        ID         int64      `json:"id"`
        From       string     `json:"from"`
        To         string     `json:"to"`
        Status     string     `json:"status"`
        EtaMinutes *int       `json:"eta_minutes,omitempty"`
        Price      *int       `json:"price,omitempty"`
        StartedAt  *time.Time `json:"started_at,omitempty"`
        FinishedAt *time.Time `json:"finished_at,omitempty"`
        Rating     *int       `json:"rating,omitempty"`
    }

    var rating sql.NullInt32

    err := h.db.QueryRow(context.Background(), `
        SELECT id, from_address, to_address, status, eta_minutes, price, started_at, finished_at, rating
        FROM rides
        WHERE client_id = $1
          AND (
                status IN ('new','assigned','in_progress')
             OR (status = 'finished' AND rating IS NULL)
          )
        ORDER BY created_at DESC
        LIMIT 1
    `, clientID).Scan(
        &resp.ID, &resp.From, &resp.To, &resp.Status,
        &resp.EtaMinutes, &resp.Price, &resp.StartedAt, &resp.FinishedAt, &rating,
    )

    if err != nil {
        c.JSON(http.StatusOK, gin.H{"ride": nil})
        return
    }

    if rating.Valid {
        v := int(rating.Int32)
        resp.Rating = &v
    }

    c.JSON(http.StatusOK, gin.H{"ride": resp})
}

/* ==================== DRIVER PROFILE (фикс: дата поездки) ==================== */

func (h *Handler) DriverProfile(c *gin.Context) {
    v, ok := c.Get("userID")
    if !ok {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Не авторизован"})
        return
    }
    userID := v.(int64)

    var profile struct {
        ID          int64   `json:"id"`
        FirstName   string  `json:"first_name"`
        LastName    string  `json:"last_name"`
        Email       string  `json:"email"`
        Phone       string  `json:"phone"`
        DriverClass *string `json:"driver_class"`

        CarMake  string `json:"car_make"`
        CarModel string `json:"car_model"`
        CarColor string `json:"car_color"`
        CarPlate string `json:"car_plate"`
    }

    err := h.db.QueryRow(context.Background(), `
        SELECT u.id, u.first_name, u.last_name, u.email, u.phone, u.driver_class,
               d.car_make, d.car_model, d.car_color, d.car_plate_number
        FROM users u
        JOIN drivers d ON d.user_id = u.id
        WHERE u.id = $1
    `, userID).Scan(
        &profile.ID, &profile.FirstName, &profile.LastName,
        &profile.Email, &profile.Phone, &profile.DriverClass,
        &profile.CarMake, &profile.CarModel, &profile.CarColor, &profile.CarPlate,
    )
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось получить профиль"})
        return
    }

    var totalTrips, todayTrips int64
    var totalIncome sql.NullInt64
    var avgRating sql.NullFloat64

    _ = h.db.QueryRow(context.Background(), `
        SELECT COUNT(*),
               COUNT(*) FILTER (WHERE finished_at::date = CURRENT_DATE),
               COALESCE(SUM(price + COALESCE(tip_amount,0)),0),
               AVG(rating::float)
        FROM rides
        WHERE driver_id = $1
          AND status IN ('finished', 'archived')
    `, userID).Scan(&totalTrips, &todayTrips, &totalIncome, &avgRating)

    rows, _ := h.db.Query(context.Background(), `
        SELECT
            from_address,
            to_address,
            COALESCE(finished_at::date, created_at::date)::text AS ride_date,
            (price + COALESCE(tip_amount, 0))::int AS total_price
        FROM rides
        WHERE driver_id = $1
          AND status IN ('finished', 'archived')
        ORDER BY finished_at DESC NULLS LAST, created_at DESC
        LIMIT 5
    `, userID)
    defer rows.Close()

    type trip struct {
        From  string `json:"from"`
        To    string `json:"to"`
        Date  string `json:"date"`
        Price int    `json:"price"`
    }

    var trips []trip
    for rows.Next() {
        var t trip
        if err := rows.Scan(&t.From, &t.To, &t.Date, &t.Price); err != nil {
            log.Printf("DriverProfile trips scan error: %v", err)
            continue
        }
        trips = append(trips, t)
    }

    c.JSON(http.StatusOK, gin.H{
        "profile": profile,
        "stats": gin.H{
            "total_trips":  totalTrips,
            "today_trips":  todayTrips,
            "total_income": totalIncome.Int64,
            "rating":       avgRating.Float64,
        },
        "trips": trips,
    })
}

/* ==================== CLIENT PROFILE & RIDES ==================== */

func (h *Handler) ClientProfile(c *gin.Context) {
    v, ok := c.Get("userID")
    if !ok {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Не авторизован"})
        return
    }
    userID, ok := v.(int64)
    if !ok {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка авторизации"})
        return
    }

    var profile struct {
        ID        int64  `json:"id"`
        FirstName string `json:"first_name"`
        LastName  string `json:"last_name"`
        Email     string `json:"email"`
        Phone     string `json:"phone"`
    }

    err := h.db.QueryRow(context.Background(), `
        SELECT id, first_name, last_name, email, phone
        FROM users
        WHERE id = $1 AND role = 'client'
    `, userID).Scan(
        &profile.ID,
        &profile.FirstName,
        &profile.LastName,
        &profile.Email,
        &profile.Phone,
    )
    if err != nil {
        log.Printf("ClientProfile query error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось получить профиль"})
        return
    }

    c.JSON(http.StatusOK, profile)
}

func (h *Handler) ClientRides(c *gin.Context) {
    v, ok := c.Get("userID")
    if !ok {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Не авторизован"})
        return
    }
    userID, ok := v.(int64)
    if !ok {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка авторизации"})
        return
    }

    rows, err := h.db.Query(context.Background(), `
        SELECT
            id,
            from_address,
            to_address,
            status,
            price,
            COALESCE(tip_amount, 0),
            COALESCE(rating, 0),
            COALESCE(finished_at::date, created_at::date)::text AS ride_date
        FROM rides
        WHERE client_id = $1
          AND status IN ('finished', 'archived')
        ORDER BY finished_at DESC NULLS LAST, created_at DESC
        LIMIT 20
    `, userID)
    if err != nil {
        log.Printf("ClientRides query error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось получить поездки"})
        return
    }
    defer rows.Close()

    type ride struct {
        ID        int64  `json:"id"`
        From      string `json:"from"`
        To        string `json:"to"`
        Status    string `json:"status"`
        Price     int    `json:"price"`
        TipAmount int    `json:"tip_amount"`
        Rating    int    `json:"rating"`
        Date      string `json:"date"`
    }

    var list []ride
    for rows.Next() {
        var r ride
        if err := rows.Scan(
            &r.ID,
            &r.From,
            &r.To,
            &r.Status,
            &r.Price,
            &r.TipAmount,
            &r.Rating,
            &r.Date,
        ); err != nil {
            log.Printf("ClientRides scan error: %v", err)
            continue
        }
        list = append(list, r)
    }

    c.JSON(http.StatusOK, gin.H{"rides": list})
}

/* ==================== DRIVER CLOSE RIDE ==================== */

func (h *Handler) CloseRideForDriver(c *gin.Context) {
    idStr := c.Param("id")
    rideID, err := strconv.ParseInt(idStr, 10, 64)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Некорректный ID заказа"})
        return
    }

    v, ok := c.Get("userID")
    if !ok {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Не авторизован"})
        return
    }
    driverID, ok := v.(int64)
    if !ok {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка авторизации"})
        return
    }

    cmd, err := h.db.Exec(context.Background(), `
        UPDATE rides
        SET status = 'archived',
            updated_at = NOW()
        WHERE id = $1
          AND driver_id = $2
          AND status = 'finished'
    `, rideID, driverID)
    if err != nil {
        log.Printf("CloseRideForDriver update error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось скрыть поездку"})
        return
    }

    if cmd.RowsAffected() == 0 {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Поездку нельзя скрыть (не найдена или неверный статус)"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Поездка скрыта"})
}

func init() {
    mrand.Seed(time.Now().UnixNano())
}
