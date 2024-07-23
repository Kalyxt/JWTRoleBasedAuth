using JWTRoleBasedAuth.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using JWTRoleBasedAuth.Auth;
using Microsoft.AspNetCore.Components.Authorization;
using JWTRoleBasedAuth.Data.Models.Users;
using MudBlazor.Services;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddScoped<JWTRoleBasedAuth.Services.LoginService>();
builder.Services.AddScoped<JWTRoleBasedAuth.Services.LogService>();
builder.Services.AddScoped<JWTRoleBasedAuth.Services.UserService>();

builder.Services.AddIdentity<JWTRoleBasedAuth.Data.Models.Users.UserDataModel,
    JWTRoleBasedAuth.Data.Models.Users.RoleDataModel>(options =>
    {
        options.User.RequireUniqueEmail = false;
        options.Password.RequireDigit = false;
        options.Password.RequireUppercase = false;
        options.SignIn.RequireConfirmedEmail = false;
        options.SignIn.RequireConfirmedPhoneNumber = false;
        options.SignIn.RequireConfirmedAccount = false;
    })
.AddEntityFrameworkStores<DataContext>()
.AddRoles<RoleDataModel>()
.AddDefaultTokenProviders();

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"] ?? string.Empty))
    };
    options.Events = new JwtBearerEvents
    {
        OnTokenValidated = context =>
        {
            var claimsIdentity = context.Principal.Identity as ClaimsIdentity;
            var roleClaims = claimsIdentity.FindAll("roles").ToList();

            foreach (var roleClaim in roleClaims)
            {
                claimsIdentity.AddClaim(new Claim(claimsIdentity.RoleClaimType, roleClaim.Value));
            }

            return Task.CompletedTask;
        }
    };
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Administrator", policy => policy.RequireRole("Administrator"));
    //options.AddPolicy("RequireAdministratorRole", policy => policy.RequireRole("Administrator"));
    //options.AddPolicy("RequireClientRole", policy => policy.RequireRole("Client"));
});

builder.Services.AddScoped<JwtAuthenticationStateProvider>();
builder.Services.AddScoped<AuthenticationStateProvider>(provider => provider.GetRequiredService<JwtAuthenticationStateProvider>());
builder.Services.AddScoped<JWTRoleBasedAuth.Auth.BlazorServerLoginService>();

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();

builder.Services.AddMudServices();

builder.Services.AddMvc();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// add db context (use in memory if you dont have local SQL server)
builder.Services.AddDbContext<DataContext>(options =>
    options.UseInMemoryDatabase("InMemoryDb"));

//builder.Services.AddDbContext<DataContext>(options =>
//{
//    var serverVersion = new MySqlServerVersion(new Version(8, 0, 29));
//    options.UseMySql(builder.Configuration.GetConnectionString("TestDb"), serverVersion);
//});


// Singletons
builder.Services.AddSingleton<JWTRoleBasedAuth.Base.AppEngine>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
else
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseAuthentication();
app.UseRouting();
app.UseAuthorization();

app.UseHttpsRedirection();

app.MapControllers();
app.MapBlazorHub();
app.MapFallbackToPage("/_Host");


app.Run();
