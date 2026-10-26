# Provider khác Zitadel

Các package lõi (`oidcauth`, `oidcfiber`, `oidctest`) chạy với mọi OpenID
Provider có discovery. Các package `zitadel/*` chỉ dành cho Zitadel.

Mọi provider đều cần ba thứ: **issuer**, **client ID / secret**, và **redirect
URI** của API đăng ký ở provider. Phần còn lại giống [setup.md](setup.md).

## 1. Google trực tiếp (không qua Zitadel)

User trong app là tài khoản Google (issuer `https://accounts.google.com`),
không có role hay back-channel logout. Dùng khi app không cần Zitadel.

### Google Cloud

1. <https://console.cloud.google.com/> → **APIs & Services** → **OAuth consent
   screen**: cấu hình như [03 §1](zitadel/03-google-zitadel-login.md#1-tạo-oauth-client-ở-google-cloud).
2. **Credentials** → **Create credentials** → **OAuth client ID**:
   - **Application type**: **Web application**.
   - **Authorized redirect URIs**:
     - `https://api.example.com/api/auth/oidc/google/callback`
     - `http://localhost:8000/api/auth/oidc/google/callback` (Google cho phép
       `http://localhost`).
   - **Create** → copy **Client ID**, **Client secret**.

### Env (nút phụ `google` bên cạnh provider chính)

```dotenv
AUTH_OIDC_PROVIDERS=google
AUTH_OIDC_GOOGLE_PROVIDER_NAME=Google
AUTH_OIDC_GOOGLE_ISSUER=https://accounts.google.com
AUTH_OIDC_GOOGLE_CLIENT_ID=<client id>.apps.googleusercontent.com
AUTH_OIDC_GOOGLE_CLIENT_SECRET=<client secret>
AUTH_OIDC_GOOGLE_REDIRECT_URL=https://api.example.com/api/auth/oidc/google/callback

# Chỉ Google Workspace: chỉ nhận tài khoản thuộc domain.
# Gmail thường không có claim hd → bị chặn hết nếu bật.
# AUTH_OIDC_GOOGLE_PARAMS=hd:example.com          # gợi ý ở màn chọn tài khoản
# AUTH_OIDC_GOOGLE_REQUIRED_CLAIMS=hd:example.com # kiểm tra thật sau login
```

Google là provider **duy nhất** của app: đặt các giá trị trên vào
`AUTH_OIDC_ISSUER`, `AUTH_OIDC_CLIENT_ID`... (không `_GOOGLE_`), redirect URI
`/api/auth/oidc/callback`.

Ai vào được: tài khoản Google có email verified trùng user app (`LINK_*`),
hoặc đã liên kết ở Profile. Google không có `end_session_endpoint`: đăng xuất
chỉ kết thúc session app.

Tự wiring:

```go
client, _ := oidcauth.New(oidcauth.Config{
	Issuer:       "https://accounts.google.com",
	ClientID:     id,
	ClientSecret: secret,
	RedirectURL:  "https://api.example.com/api/auth/oidc/google/callback",
	CookieSecret: cookieSecret,
	CookiePath:   "/api/auth/oidc/",
})
h := oidcfiber.New(client, oidcfiber.Options{
	LoginOptions: func(*fiber.Ctx) []oidcauth.LoginOption {
		return []oidcauth.LoginOption{oidcauth.WithParam("hd", "example.com")}
	},
	OnSuccess: func(c *fiber.Ctx, res *oidcauth.Result) error {
		if res.Identity.Claims["hd"] != "example.com" { /* từ chối */ }
		...
	},
})
```

## 2. Keycloak

1. Admin console → chọn realm → **Clients** → **Create client**:
   - **Client type**: OpenID Connect; **Client ID**: `billing-web` → **Next**.
   - **Client authentication**: On (confidential); **Standard flow**: On →
     **Next**.
   - **Valid redirect URIs**: `https://api.example.com/api/auth/oidc/callback`;
     **Valid post logout redirect URIs**: `https://app.example.com/auth/login`
     → **Save**.
2. Tab **Credentials** → copy **Client secret**.
3. Tab **Advanced** (hoặc **Settings** → **Logout settings**): **Backchannel
   logout URL** `https://api.example.com/api/auth/oidc/backchannel-logout`,
   bật **Backchannel logout session required**.

```dotenv
AUTH_OIDC_ISSUER=https://keycloak.example.com/realms/<realm>
AUTH_OIDC_CLIENT_ID=billing-web
AUTH_OIDC_CLIENT_SECRET=<secret>
```

Role: Keycloak để role trong `realm_access.roles` và
`resource_access.<client>.roles`, không phải `roles`. Đặt `RoleExtractor`:

```go
RoleExtractor: func(claims map[string]any) []string {
	var out []string
	ra, _ := claims["realm_access"].(map[string]any)
	roles, _ := ra["roles"].([]any)
	for _, r := range roles {
		if s, ok := r.(string); ok {
			out = append(out, s)
		}
	}
	return out
},
```

Hoặc thêm mapper **User Realm Role** với **Token Claim Name** `roles` vào
client scope để role mặc định đọc được.

## 3. Microsoft Entra ID

1. Azure portal → **Microsoft Entra ID** → **App registrations** → **New
   registration**: tên, **Supported account types**, **Redirect URI** chọn
   **Web** = `https://api.example.com/api/auth/oidc/callback` → **Register**.
2. **Certificates & secrets** → **New client secret** → copy **Value**.
3. **Authentication** → **Front-channel logout URL** tuỳ chọn.
4. **App roles** → tạo role; gán ở **Enterprise applications** → **Users
   and groups**. Role nằm ở claim `roles` (mặc định đọc được).

```dotenv
AUTH_OIDC_ISSUER=https://login.microsoftonline.com/<tenant id>/v2.0
AUTH_OIDC_CLIENT_ID=<Application (client) ID>
AUTH_OIDC_CLIENT_SECRET=<secret value>
```

Tenant `common` / `organizations` có issuer thay đổi theo tenant của user,
không khớp discovery: dùng tenant ID cụ thể. Email Entra không phải lúc nào
cũng có `email_verified`; liên kết theo `preferred_username` hoặc liên kết thủ
công.

## 4. Auth0

1. Dashboard → **Applications** → **Create Application** → **Regular Web
   Applications**.
2. **Settings**: **Allowed Callback URLs**
   `https://api.example.com/api/auth/oidc/callback`, **Allowed Logout URLs**
   `https://app.example.com/auth/login` → **Save Changes**.
3. Copy **Domain**, **Client ID**, **Client Secret**.

```dotenv
AUTH_OIDC_ISSUER=https://<tenant>.auth0.com/   # có "/" cuối, đúng như discovery
AUTH_OIDC_CLIENT_ID=<client id>
AUTH_OIDC_CLIENT_SECRET=<client secret>
```

Role: thêm Action đặt custom claim (vd. `https://example.com/roles`) rồi đọc
bằng `RoleExtractor`.

## 5. Provider bất kỳ

1. Lấy issuer: `curl <issuer>/.well-known/openid-configuration | jq .issuer`;
   giá trị này phải khớp từng ký tự với `AUTH_OIDC_ISSUER`.
2. Tạo client loại "web / confidential", luồng Authorization Code, đăng ký
   redirect URI của API.
3. Provider không hỗ trợ `userinfo`: đặt `SkipUserInfo: true`.
4. Role ở claim khác: `RoleExtractor`.
5. Thử end-to-end mà không cần provider thật: `oidctest.NewProvider`.
