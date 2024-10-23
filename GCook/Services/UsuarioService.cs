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
        private readonly AppContext _contexto;
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
            _emailSender = emailSender;
            _logger = logger;
        }

        public async Task<bool> ConfirmarEmail(string userId, string code)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return false;
            }
            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
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
            var usuario = await _contexto.Usuarios.Where(u => u.UsuarioId == userId).SingleOrDefaultAsync();
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
            string UserName = login.Email;
            if (Helper.IsValidEmail(login.Email))
        }
    }
