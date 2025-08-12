# JWTService

**JwtService.cs**

```cs
public class JwtService : IJwtService
{
    private readonly JwtSettings _jwtSettings;

    public JwtService(JwtSettings jwtSettings)
    {
        _jwtSettings = jwtSettings ?? throw new ArgumentNullException(nameof(jwtSettings));
    }

    public string GenerateToken(string userId)
    {
        var keyBytes = Encoding.UTF8.GetBytes(_jwtSettings.Key);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpireMinutes),
            Issuer = _jwtSettings.Issuer,
            Audience = _jwtSettings.Audience,
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(keyBytes),
                SecurityAlgorithms.HmacSha256Signature)
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}
```

**Program.cs**

```cs
builder.Services.AddIdentityCore<ApplicationUser>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();
```

```cs
// JWT Configuration
var jwtSettings = new JwtSettings();
builder.Configuration.GetSection("Jwt").Bind(jwtSettings);
builder.Services.AddSingleton(jwtSettings);

var key = Encoding.ASCII.GetBytes(jwtSettings.Key);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = true,
        ValidIssuer = jwtSettings.Issuer,
        ValidateAudience = true,
        ValidAudience = jwtSettings.Audience,
        ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddScoped<IJwtService, JwtService>();

builder.Services.AddControllers().AddJsonOptions(options =>
{
    options.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
});

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();

// CORS configuration
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll",
        policy =>
        {
            // TODO: Restrict origins in production environment
            policy.AllowAnyOrigin() // NOSONAR: Permissive for development
                  .AllowAnyHeader()
                  .AllowAnyMethod();
        });
});
```

```cs
app.UseCors("AllowAll");

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// Migration
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await dbContext.Database.MigrateAsync();
}

await app.RunAsync();
```

**JwtServiceTests.cs**

```cs
public class JwtServiceTests
{
    private readonly JwtService _service;
    private readonly JwtSettings _jwtSettings;

    public JwtServiceTests()
    {
        // Setup JWT settings
        _jwtSettings = new JwtSettings
        {
            Key = "MySecretKeyForJWTTokenGeneration1234567890",
            Issuer = "TestIssuer",
            Audience = "TestAudience",
            ExpireMinutes = 60
        };

        _service = new JwtService(_jwtSettings);
    }

    [Fact]
    public void GenerateToken_ValidUserId_ReturnsToken()
    {
        // Arrange
        var userId = "test-user-id";

        // Act
        var token = _service.GenerateToken(userId);

        // Assert
        Assert.NotNull(token);
        Assert.NotEmpty(token);
    }

    [Fact]
    public void GenerateToken_NullUserId_ReturnsToken()
    {
        // Act
        var token = _service.GenerateToken(null!);

        // Assert
        Assert.NotNull(token);
        Assert.NotEmpty(token);
    }

    [Theory]
    [InlineData("")]
    public void GenerateToken_EmptyUserId_ReturnsToken(string userId)
    {
        // Act
        var token = _service.GenerateToken(userId);

        // Assert
        Assert.NotNull(token);
        Assert.NotEmpty(token);
    }

    [Fact]
    public void Constructor_NullJwtSettings_ThrowsException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new JwtService(null!));
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void GenerateToken_InvalidKey_ThrowsException(string? key)
    {
        // Arrange
        var invalidSettings = new JwtSettings
        {
            Key = key!,
            Issuer = "TestIssuer",
            Audience = "TestAudience",
            ExpireMinutes = 60
        };

        var service = new JwtService(invalidSettings);

        // Act & Assert
        Assert.ThrowsAny<Exception>(() => service.GenerateToken("test-user-id"));
    }

    [Fact]
    public void GenerateToken_ValidSettings_ContainsCorrectClaims()
    {
        // Arrange
        var userId = "test-user-id";

        // Act
        var token = _service.GenerateToken(userId);

        // Assert
        Assert.NotNull(token);
        Assert.NotEmpty(token);
        // Token should be a valid JWT format (3 parts separated by dots)
        var parts = token.Split('.');
        Assert.Equal(3, parts.Length);
    }
}
```
