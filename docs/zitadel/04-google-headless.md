# 04. Google qua Zitadel, không qua trang Zitadel (`IDP_ID`)

Kết quả: nút "Đăng nhập bằng Google"; trình duyệt chỉ thấy trang Google. User
trong app vẫn là **user Zitadel** (role, back-channel logout, project check
như [01](01-web-app.md)/[02](02-roles-and-orgs.md)).

Cách làm: API tự đóng vai trang login của Zitadel qua API v2 (giống Login
V2), bằng một service account có role instance `IAM_LOGIN_CLIENT`.

Cần làm trước: [01](01-web-app.md), và [03 §1–§3](03-google-zitadel-login.md)
(OAuth client Google + IdP Google trong Zitadel, đã **Activate**).

## 1. Luồng

```mermaid
sequenceDiagram
    autonumber
    participant B as Trình duyệt
    participant A as API
    participant Z as Zitadel
    participant G as Google
    B->>A: GET /api/auth/oidc/google/login
    A->>A: Start: flow cookie (state, nonce, PKCE)
    A->>Z: GET /oauth/v2/authorize (không theo redirect)
    Z-->>A: 302 …?authRequest=V2_…
    A->>A: Lưu auth request ID trong TicketStore (ticket rq)
    A->>Z: POST /v2/idp_intents (PAT)
    Z-->>A: URL Google
    A-->>B: 302 → Google + Set-Cookie flow
    B->>G: Đăng nhập Google
    G-->>B: 302 → Zitadel /idps/callback
    B->>Z: /idps/callback
    Z-->>B: 302 → /api/auth/oidc/google/idp/callback?rq&id&token
    B->>A: idp callback
    A->>Z: Đọc intent, tìm / liên kết / tạo user, kiểm tra org, MFA
    A->>Z: POST /v2/sessions, POST /v2/oidc/auth_requests/{id}
    Z-->>A: redirect URI của client ?code&state
    A-->>B: 302 → /api/auth/oidc/callback?code&state
    B->>A: callback (flow cookie) → đổi code, kiểm tra như login thường
    A-->>B: 302 → SPA /auth/callback?ticket=…
```

## 2. Tạo service account và PAT

Làm một lần cho mỗi instance; mọi app dùng chung được (hoặc mỗi app một
account để thu hồi riêng).

1. Chọn org nội bộ (vd. org mặc định) → menu **Users** → tab **Service
   Accounts** → **New**.
2. Điền:
   - **User Name**: vd. `login-client-billing`.
   - **Name**: vd. `Login client Billing`.
   - **Description**: tuỳ.
   - **Access Token Type**: **Bearer**.
3. **Create**. Trang của service account mở ra.
4. Mục **Personal Access Tokens** → **New** → hộp thoại **Generate new
   Personal Access Token**: chọn ngày hết hạn (tuỳ, nhớ lịch xoay vòng) →
   tạo.
5. Hộp thoại "Make sure to copy your personal access token. You won't be able
   to see it again!" → copy token → lưu vào secret store.

## 3. Gán role instance `IAM_LOGIN_CLIENT`

Role này cho phép tạo session và hoàn tất auth request thay trang login.
Role org hay project **không** đủ.

1. **Default settings** (trang Instance) → khung **Administrators** → nút
   **(+)**.
2. Hộp thoại **Add an Administrator**: tìm service account ở §2.
3. Tick role **IAM_LOGIN_CLIENT** ("Has permission to manage login
   applications") → **Add** / **Save**.

Kiểm tra: khung **Administrators** có service account với role
`IAM_LOGIN_CLIENT`.

## 4. Biến env

```dotenv
# Provider chính (01) giữ nguyên.

# PAT ở §2. Dùng _FILE nếu secret được mount thành file.
AUTH_OIDC_SERVICE_TOKEN=<PAT>
# AUTH_OIDC_SERVICE_TOKEN_FILE=/run/secrets/zitadel-login-pat

AUTH_OIDC_PROVIDERS=google
AUTH_OIDC_GOOGLE_PROVIDER_NAME=Google
AUTH_OIDC_GOOGLE_VIA=sso                       # dùng client của provider chính
AUTH_OIDC_GOOGLE_IDP_ID=<Identity Provider ID> # 03 §3 bước 6
AUTH_OIDC_GOOGLE_EXTRA_SCOPES=urn:zitadel:iam:org:id:<Organization ID>
```

| Biến | Bắt buộc | Ghi chú |
|---|---|---|
| `AUTH_OIDC_SERVICE_TOKEN[_FILE]` | Có (hoặc `AUTH_OIDC_GOOGLE_SERVICE_TOKEN[_FILE]`) | Thiếu thì API lỗi lúc khởi động |
| `AUTH_OIDC_GOOGLE_VIA` | Có | `IDP_ID` luôn đi cùng `VIA` |
| `AUTH_OIDC_GOOGLE_IDP_ID` | Có | ID của IdP Google trong Zitadel |
| `AUTH_OIDC_GOOGLE_EXTRA_SCOPES` | Nên có | Org mà user được tìm / tạo. Phải là org sở hữu IdP, hoặc org đang bật IdP cấp instance |

**Không** đăng ký thêm redirect URI nào ở Zitadel hay Google:

- Zitadel tự quay về `https://<api>/api/auth/oidc/google/idp/callback` (API
  truyền URL này khi tạo intent; host lấy từ `AUTH_OIDC_REDIRECT_URL`).
- Code cuối cùng vẫn về `AUTH_OIDC_REDIRECT_URL` của provider chính.

Khởi động lại API.

Tự wiring:

```go
api := zitadel.New(client.Config().Issuer, os.Getenv("ZITADEL_LOGIN_PAT"), nil)
google := zitadelfiber.New(client, zitadel.NewIDPLogin(api, googleIDPID), zitadelfiber.Options{
	Tickets:     tickets, // dùng chung TicketStore với ticket login được
	CallbackURL: "https://api.example.com/api/auth/oidc/google/idp/callback",
	LoginOptions: func(*fiber.Ctx) []oidcauth.LoginOption {
		return []oidcauth.LoginOption{oidcauth.WithExtraScopes("urn:zitadel:iam:org:id:" + orgID)}
	},
	OnError: func(c *fiber.Ctx, err error) error { /* map lỗi, xem §6 */ },
})
app.Get("/api/auth/oidc/google/login", google.Login)
app.Get("/api/auth/oidc/google/idp/callback", google.Callback)
// /api/auth/oidc/callback vẫn là oidcfiber.Handler.Callback của client
```

`CookiePath` của client phải bao cả `/api/auth/oidc/google/idp/callback` và
`/api/auth/oidc/callback` (vd. `/api/auth/oidc/`).

## 5. Ai đăng nhập được

API làm giống trang login của Zitadel, theo tuỳ chọn của IdP (03 §2):

```mermaid
flowchart TD
    I[Tài khoản Google] --> L{Đã liên kết<br/>user Zitadel?}
    L -- có --> U[User đó]
    L -- không --> AL{Auto-linking}
    AL -- Check for existing Email<br/>và email Google verified --> E{Số user trùng email<br/>trong org của scope}
    AL -- Check for existing Username --> E
    AL -- Disabled --> AC
    E -- 1 --> LA{Org của user: External Login allowed<br/>và IdP bật Account linking allowed?}
    LA -- có --> LK[Liên kết rồi dùng user đó]
    LA -- không --> NA[not_allowed]
    E -- 0 hoặc nhiều --> AC{Automatic creation?}
    AC -- có, Google trả đủ họ + tên --> C[Tạo user trong org của scope<br/>hoặc org mặc định]
    AC -- có, thiếu họ/tên --> NL[not_linked]
    AC -- không --> NL
    U & LK & C --> K{User active?}
    K -- không --> IN[user_inactive]
    K -- có --> O{Thuộc org của scope?}
    O -- không --> NA
    O -- có --> M{Org: Force MFA for all users<br/>và không phải local only?}
    M -- có --> MFA[mfa_required]
    M -- không --> P{Project check<br/>02 §2}
    P -- không đạt --> AD[access_denied]
    P -- đạt --> OK[Đăng nhập]
```

Lưu ý:

- Không có scope org, một email trùng ở **nhiều** org bị từ chối (liên kết
  sẽ là đoán) và user mới được tạo ở **org mặc định**. Hãy luôn đặt
  `EXTRA_SCOPES` org.
- Auto-link theo email chỉ khi Google báo email **verified** (Gmail luôn
  verified).

### 5.1 MFA

Trang login của Zitadel hỏi được mã MFA, API thì không. Nếu org của user bật
**Force MFA for all users**, login Google qua `IDP_ID` trả `mfa_required`.

Cách xử lý (org → **Settings** → **Login Behavior and Security**):

- Chọn **Force MFA for local authenticated users only**: user mật khẩu vẫn bị
  ép MFA, user đăng nhập bằng Google thì không (Google đã có xác thực của
  nó). **Save**.
- Hoặc dùng [03](03-google-zitadel-login.md) (có trang Zitadel) cho org cần
  MFA cho cả user Google.

## 6. Mã lỗi (template)

| Lỗi thư viện | Mã trên `/auth/login?error=` | Nguyên nhân thường gặp |
|---|---|---|
| `zitadel.ErrNotLinked` | `not_linked` | Không có user, IdP không auto-link / auto-create, hoặc thiếu họ/tên khi auto-create, hoặc email trùng nhiều org |
| `zitadel.ErrNotAllowed` | `not_allowed` | User ở org khác scope, org tắt **External Login allowed**, IdP không bật cho org / không cho linking |
| `zitadel.ErrAccessDenied` | `access_denied` | Project check (02 §2) |
| `zitadel.ErrUserInactive` | `user_inactive` | User Zitadel bị deactivate / lock |
| `zitadel.ErrMFARequired` | `mfa_required` | §5.1 |
| `zitadel.ErrAuthRequestExpired`, `oidcauth.ErrInvalidState` | `state_expired` | Đứng ở trang Google quá `FlowTTL` (10 phút), ấn Back / mở lại link cũ |
| `zitadel.ErrIntentFailed` | `oidc_failed` | User huỷ ở Google |
| `*zitadel.APIError` 4xx khác | `oidc_failed` | Thường là PAT thiếu `IAM_LOGIN_CLIENT` (403) hoặc PAT hết hạn (401) |
| Lỗi mạng / 5xx | `idp_unavailable` | Zitadel không truy cập được |

Log API ghi lý do chi tiết (`zitadel idp login refused` kèm `reason`).

## 7. Thử

1. Trang login SPA → **Google** → chỉ thấy trang Google → quay về app đã đăng
   nhập.
2. Console Zitadel → **Users** → user đó → mục identity providers có Google;
   mục sessions có session mới.
3. Thử các ca từ chối: tài khoản Google không có user (khi tắt auto-create)
   → `not_linked`; user bị **Deactivate** → `user_inactive`.

## 8. Vì sao không đăng ký app làm "Custom base URL for the new Login UI"?

Zitadel cho mỗi application một **Custom base URL for the new Login UI**,
nhưng khi instance bật Login V2 bắt buộc (**Default settings** →
**Features** → Login V2) thì URL theo app bị bỏ qua. Vì vậy API tự gọi
authorize phía server, lấy `authRequest=V2_…` rồi xử lý như một login UI.
