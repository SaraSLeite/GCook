using System.ComponentModel.DataAnnotations;

namespace GCook.ViewModels;
    public class RegistroVM
    {
        [Display(Name = "Nome Completo", Prompt = "Informe seu Nome Completo")]        
        [Required(ErrorMessage = "Por favor, informe seu Nome")]
        [StringLength(60, ErrorMessage = "O nome deve possuir no máximo 60 caracteres")]
        public string Nome { get; set; }
    
        [DataType(DataType.Date)]
        [Display(Name = "Data de Nascimento", Prompt = "Informe sua data de Nascimento")]        
        [Required(ErrorMessage = "Por favor, informe sua data de Nascimento")]
        public string DataNascimento { get; set; } = null;

        [Display(Name = "Informe seu Email")]        
        [Required(ErrorMessage = "Por favor, informe seu Email")]
        [EmailAddress(ErrorMessage = "Por favor, Informe um Email Válido!")]
        [StringLength(100, ErrorMessage = "O email deve possuir no máximo 100 caracteres")]
        public string Email { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Senha de Acesso", Prompt = "Informe uma Senha de Acesso")]        
        [Required(ErrorMessage ="Por favor, informe sua Senha de Acesso")]
        [StringLength(20, MinimumLength = 6, ErrorMessage = "A Senha deve possuir no minimo 6 e no máximo 20 caracteres")]
        public string Senha { get; set; }

        [DataType(DataType.Password)]    
        [Display(Name = "Confirmar Senha de Acesso", Prompt = "Confirme sua Senha de Acesso")]        
        [Compare("Senha", ErrorMessage ="As Senhas não Conferem.")]
        public string ConfirmacaoSenha { get; set; }

        public IFormFile Foto { get; set; }
        
        public bool Termos { get; set; } = false;
        
        public bool Enviado { get; set; } = false;
    }