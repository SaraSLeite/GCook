using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using GCook.Data;
using GCook.ViewModels;
using Microsoft.EntityFrameworkCore;
using GCook.Helpers;
using GCook.Models;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using System.Text.Encodings.Web;

namespace GCook.Services;

public class UsuarioService : IUsuarioService
{
    private readonly AppDbContext _contexto;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IUserStore<IdentityUser> _userStore;
    private readonly IUserEmailStore<IdentityUser> _emailStore;
    private readonly IWebHostEnvironment _hostEnvironment;
    private readonly IEmailSender _emailSender;
    private readonly ILogger<UsuarioService> _logger;

    public UsuarioService(
        AppDbContext contexto,
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager,
        IHttpContextAccessor httpContextAccessor,
        IUserStore<IdentityUser> userStore,
        IWebHostEnvironment hostEnvironment,
        IEmailSender emailSender, // Correção aqui
        ILogger<UsuarioService> logger
    )
    {
        _contexto = contexto;
        _signInManager = signInManager;
        _userManager = userManager;
        _httpContextAccessor = httpContextAccessor;
        _userStore = userStore;
        _emailStore = (IUserEmailStore<IdentityUser>)_userStore;
        _hostEnvironment = hostEnvironment;
        _emailSender = emailSender; // Agora inicializado corretamente
        _logger = logger;
    }

    public async Task<bool> ConfirmarEmail(string userId, string code)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return false;
        }

        // Tratamento de erro ao decodificar o código
        try
        {
            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
        }
        catch
        {
            return false; // Retorna false se a decodificação falhar
        }

        var result = await _userManager.ConfirmEmailAsync(user, code);
        return result.Succeeded;
    }

    public async Task<UsuarioVM> GetUsuarioLogado()
    {
        var userId = _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
        {
            return null;
        }

        var userAccount = await _userManager.FindByIdAsync(userId);
        var usuario = await _contexto.Usuarios.SingleOrDefaultAsync(u => u.UsuarioId == userId);

        if (usuario == null) // Verificação para evitar referência nula
        {
            return null;
        }

        var perfis = string.Join(", ", await _userManager.GetRolesAsync(userAccount));
        var admin = await _userManager.IsInRoleAsync(userAccount, "Administrador");

        UsuarioVM usuarioVM = new()
        {
            UsuarioId = userId,
            Nome = usuario.Nome,
            DataNascimento = usuario.DataNascimento,
            Foto = usuario.Foto,
            Email = userAccount.Email,
            UserName = userAccount.UserName,
            Perfil = perfis,
            IsAdmin = admin
        };

        return usuarioVM;
    }

    public async Task<SignInResult> LoginUsuario(LoginVM login)
    {
        string userName = login.Email;

        if (Helper.IsValidEmail(login.Email))
        {
            var user = await _userManager.FindByEmailAsync(login.Email);
            if (user != null)
                userName = user.UserName;
        }

        var result = await _signInManager.PasswordSignInAsync(
            userName, login.Senha, login.Lembrar, lockoutOnFailure: true
        );

        if (result.Succeeded)
            _logger.LogInformation($"Usuário {login.Email} acessou o sistema");
        if (result.IsLockedOut)
            _logger.LogWarning($"Usuário {login.Email} está bloqueado");

        return result;
    }

    public async Task LogoffUsuario()
    {
        var userEmail = _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Email); 
        _logger.LogInformation($"Usuário {userEmail} fez logoff");
        await _signInManager.SignOutAsync();
    }

    public async Task<List<string>> RegistrarUsuario(RegistroVM registro)
    {
        var user = Activator.CreateInstance<IdentityUser>();

        await _userStore.SetUserNameAsync(user, registro.Email, CancellationToken.None);
        await _emailStore.SetEmailAsync(user, registro.Email, CancellationToken.None);
        var result = await _userManager.CreateAsync(user, registro.Senha);

        if (result.Succeeded)
        {
            _logger.LogInformation($"Novo usuário registrado com o email {user.Email}");

            var userId = await _userManager.GetUserIdAsync(user);
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
            var url = $"http://localhost:5143/Account/ConfirmarEmail?userId={userId}&code={code}";

            await _userManager.AddToRoleAsync(user, "Usuário");

            await _emailSender.SendEmailAsync(registro.Email, "GCook - Criação de Conta", GetConfirmEmailHtml(HtmlEncoder.Default.Encode(url)));

            // Cria a conta pessoal do usuário
            Usuario usuario = new()
            {
                UsuarioId = userId,
                DataNascimento = registro.DataNascimento ?? DateTime.Now,
                Nome = registro.Nome
            };

            if (registro.Foto != null)
            {
                string fileName = userId + Path.GetExtension(registro.Foto.FileName);
                string uploads = Path.Combine(_hostEnvironment.WebRootPath, @"img\usuarios");
                string newFile = Path.Combine(uploads, fileName);
                using (var stream = new FileStream(newFile, FileMode.Create))
                {
                    await registro.Foto.CopyToAsync(stream); // Usar CopyToAsync para evitar bloqueio
                }
                usuario.Foto = @"\img\usuarios\" + fileName;
            }

            _contexto.Add(usuario);
            await _contexto.SaveChangesAsync();

            return new List<string>(); // Retornando lista vazia em caso de sucesso
        }

        List<string> errors = new();
        foreach (var error in result.Errors)
        {
            errors.Add(TranslateIdentityErrors.TranslateErrorMessage(error.Code));
        }
        return errors;
    }

    private string GetConfirmEmailHtml(string url)
    {
        var email = $@"
        <!DOCTYPE html>
        <html>
        <head>
        <meta charset=""utf-8"">
        <meta http-equiv=""x-ua-compatible"" content=""ie=edge"">
        <title>Email Confirmation</title>
        <meta name=""viewport"" content=""width=device-width, initial-scale=1"">
        <style type=""text/css"">
        /* styles omitted for brevity */
        </style>
        </head>
        <body style=""background-color: #e9ecef;"">
        <div class=""preheader"" style=""display: none; max-width: 0; max-height: 0; overflow: hidden; font-size: 1px; line-height: 1px; color: #fff; opacity: 0;"">
            Website GCoock - Confirmação de Conta.
        </div>
        <table border=""0"" cellpadding=""0"" cellspacing=""0"" width=""100%"">
            <tr>
                <td align=""center"" bgcolor=""#e9ecef"">
                    <table border=""0"" cellpadding=""0"" cellspacing=""0"" width=""100%"" style=""max-width: 600px;"">
                        <tr>
                            <td align=""center"" valign=""top"" style=""padding: 36px 24px;"">
                                <a href=""localhost:5143"" target=""_blank"" style=""display: inline-block;"">
                                    <img src=""https://github.com/3-MTecPi/GCookA/blob/b2cff88fe35a5c5283b04639ca5caa43ee91a6bb/GCook/wwwroot/img/logo.png?raw=true"" alt=""Logo"" border=""0"" width=""100"" style=""display: block; width: 100px; max-width: 400px; min-width: 100px;"">
                                </a>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
            <tr>
                <td align=""center"" bgcolor=""#e9ecef"">
                    <table border=""0"" cellpadding=""0"" cellspacing=""0"" width=""100%"" style=""max-width: 600px;"">
                        <tr>
                            <td align=""left"" bgcolor=""#ffffff"" style=""padding: 36px 24px 0; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; border-top: 3px solid #d4dadf;"">
                                <h1 style=""margin: 0; font-size: 32px; font-weight: 700; letter-spacing: -1px; line-height: 48px;"">Confirmação de Endereço de Email</h1>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
            <tr>
                <td align=""center"" bgcolor=""#e9ecef"">
                    <table border=""0"" cellpadding=""0"" cellspacing=""0"" width=""100%"" style=""max-width: 600px;"">
                        <tr>
                            <td align=""left"" bgcolor=""#ffffff"" style=""padding: 24px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 16px; line-height: 24px;"">
                                <p style=""margin: 0;"">Para confirmar seu endereço de e-mail, clique no botão abaixo:</p>
                            </td>
                        </tr>
                        <tr>
                            <td align=""left"" bgcolor=""#ffffff"" style=""padding: 12px 24px 24px;"">
                                <table border=""0"" cellpadding=""0"" cellspacing=""0"" width=""100%"">
                                    <tr>
                                        <td align=""center"" bgcolor=""#f9c74f"" style=""border-radius: 6px;"">
                                            <a href=""{url}"" target=""_blank"" style=""display: inline-block; padding: 16px 30px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 16px; color: #ffffff; text-decoration: none; border-radius: 6px;"">Confirmar E-mail</a>
                                        </td>
                                    </tr>
                                </table>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
            <tr>
                <td align=""center"" bgcolor=""#e9ecef"">
                    <table border=""0"" cellpadding=""0"" cellspacing=""0"" width=""100%"" style=""max-width: 600px;"">
                        <tr>
                            <td align=""left"" bgcolor=""#ffffff"" style=""padding: 24px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 16px; line-height: 24px;"">
                                <p style=""margin: 0;"">Se você não criou uma conta, nenhuma ação adicional é necessária.</p>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
        </body>
        </html>";

        return email;
    }
}
