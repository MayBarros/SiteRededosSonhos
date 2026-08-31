import React, { useState } from 'react';
import Modal from './Modal'; 
import "../styles/Footer.css";


const textoTermosUso = (
  <p style={{ whiteSpace: 'pre-line' }}>
  <strong>Termos de uso da Rede dos Sonhos</strong><br /><br />

    A Rede dos Sonhos está comprometida em oferecer um ambiente seguro, humano e transparente. Esta política define diretrizes de conduta, proteção de dados e limites de responsabilidade da plataforma.<br /><br />

    <strong>1. Registro e Termo de Comprometimento</strong><br />
    Todos os usuários, ao se cadastrarem, devem aceitar um Termo de Comprometimento. Ao utilizar a plataforma, o usuário declara que:<br />
    • Age de boa-fé;<br />
    • Não utiliza a plataforma para fins ilícitos, enganosos ou abusivos;<br />
    • Compreende que a plataforma não se responsabiliza pela realização dos "sonhos";<br />
    • Entende que as negociações são feitas diretamente entre as partes;<br />
    • Assume responsabilidade pelas informações trocadas fora da plataforma.<br /><br />

    <strong>2. Transparência e Registro de Conversas</strong><br />
    Todas as conversas feitas por meio do chat da Rede dos Sonhos ficam registradas. Esses registros servem como garantia de transparência e responsabilização em caso de denúncias ou disputas. A plataforma pode acessar esses dados mediante denúncia ou exigência legal.<br /><br />

    <strong>3. Limites de Responsabilidade</strong><br />
    A Rede dos Sonhos atua apenas como um meio de conexão. Não garante, fiscaliza ou intermedia a execução de sonhos ou promessas. Não se responsabiliza por acordos, serviços ou transferências financeiras entre os usuários.<br /><br />

    <strong>4. Interações Fora da Plataforma</strong><br />
    Se os usuários decidirem continuar a interação fora do site (WhatsApp, redes sociais, encontros etc.), a Rede dos Sonhos não se responsabiliza pelas consequências dessas ações. O compartilhamento de dados pessoais e a decisão de continuar a comunicação externamente são de responsabilidade dos usuários.<br /><br />

    <strong>5. Conduta e Denúncias</strong><br />
    Espera-se que todos ajam com ética e respeito. Comportamentos inadequados, abusivos ou suspeitos devem ser denunciados e serão analisados com base nos Termos de Uso e nesta Política.<br /><br />

    <strong>6. Privacidade e Proteção de Dados</strong><br />
    A Rede dos Sonhos protege os dados pessoais de seus usuários conforme as leis de proteção de dados. Para mais informações sobre coleta, uso e exclusão de dados, consulte nossa Política de Privacidade.<br /><br />

    <strong>7. Atualizações da Política</strong><br />
    Esta política pode ser modificada a qualquer momento para melhor atender os usuários. Notificações sobre alterações serão feitas na plataforma ou por outros meios adequados.<br /><br />

    <em>Última atualização: julho de 2025</em>
  </p>
  
);

const textoPoliticaPrivacidade = (
  <p style={{ whiteSpace: 'pre-line' }}>
     <strong>Política de Privacidade da Rede dos Sonhos</strong><br /><br />

    A Rede dos Sonhos ("Plataforma") está comprometida com a privacidade e a segurança dos dados de seus usuários, conforme a Lei Geral de Proteção de Dados (LGPD - Lei nº 13.709/2018). Esta política descreve como coletamos, usamos, armazenamos, compartilhamos e protegemos suas informações pessoais.<br /><br />

    <strong>1. Definições</strong><br />
    • <em>Dados Pessoais:</em> Informações que identifiquem ou possam identificar uma pessoa.<br />
    • <em>Titular:</em> Pessoa a quem os dados se referem.<br />
    • <em>Tratamento:</em> Toda operação com dados pessoais.<br />
    • <em>Controlador:</em> Quem decide sobre o tratamento (Rede dos Sonhos).<br />
    • <em>Operador:</em> Quem executa o tratamento em nome do Controlador.<br /><br />

    <strong>2. Dados Coletados e Finalidade</strong><br />
    <u>2.1. Fornecidos por Você:</u><br />
    • Nome, e-mail, telefone (opcional), localização, data de nascimento, foto (opcional).<br />
    • Usados para criar sua conta, conectar usuários e garantir segurança e moderação.<br /><br />
    <u>2.2. Coletados Automaticamente:</u><br />
    • Dados de navegação (IP, navegador, sistema operacional).<br />
    • Cookies usados para autenticação, análise e personalização da experiência.<br /><br />

    <strong>3. Bases Legais (LGPD)</strong><br />
    • Execução de contrato (criação de conta e uso da plataforma).<br />
    • Cumprimento legal.<br />
    • Legítimo interesse (segurança, melhorias).<br />
    • Consentimento (em casos específicos, como marketing).<br /><br />

    <strong>4. Compartilhamento de Dados</strong><br />
    • Com outros usuários (nome, cidade, descrição do sonho, foto, se houver).<br />
    • Com prestadores de serviço contratados.<br />
    • Por obrigações legais ou judiciais.<br />
    • Para proteger direitos da plataforma e seus usuários.<br />
    • Em casos de fusão, aquisição ou reorganização societária.<br /><br />

    <strong>5. Moderação de Conteúdo e Chats</strong><br />
    • As conversas e publicações são moderadas.<br />
    • Buscamos prevenir e agir contra:<br />
    - Racismo, assédio, preconceito, violência de gênero, discurso de ódio.<br />
    - Atividades ilícitas, abusos ou fraudes.<br />
    • Medidas incluem advertência, suspensão ou exclusão de contas.
    • A moderação pode resultar na exclusão de conteúdo, suspensão ou exclusão de contas, conforme a gravidade da violação e nossos Termos de Uso.
    • Os dados coletados para fins de moderação serão tratados com a máxima confidencialidade e utilizados estritamente para as finalidades de segurança e integridade da plataforma.<br /><br />

    <strong>6. Segurança dos Dados</strong><br />
    • Rede dos Sonhos emprega medidas técnicas e organizacionais de segurança para proteger seus dados pessoais contra acesso não autorizado, alteração, divulgação ou destruição.<br />
    • Treinamos nossa equipe e seguimos boas práticas de proteção.<br />
    • Nenhum sistema é 100% seguro, mas tomamos todas as precauções possíveis.<br /><br />

    <strong>7. Retenção dos Dados</strong><br />
    • Seus dados são mantidos enquanto necessários para os fins descritos.<br />
    • Também podemos manter dados para obrigações legais e segurança da plataforma.<br /><br />

    <strong>8. Seus Direitos como Titular</strong><br />
    Você pode, a qualquer momento:<br />
    • Confirmar e acessar seus dados;<br />
    • Corrigir dados incompletos ou incorretos;<br />
    • Solicitar anonimização, bloqueio ou exclusão;<br />
    • Solicitar portabilidade ou eliminação de dados;<br />
    • Saber com quem compartilhamos dados;<br />
    • Revogar consentimento dado previamente;<br />
    • Opor-se ao tratamento de dados que desrespeitem a LGPD.<br /><br />

    <strong>9. Contato do Encarregado (DPO)</strong><br />
    Para exercer seus direitos ou tirar dúvidas, entre em contato com nosso Encarregado de Dados (DPO):<br />
    <em>[Inserir e-mail do DPO]</em><br /><br />

    <strong>10. Alterações nesta Política</strong><br />
    Podemos atualizar esta política periodicamente. A versão mais recente estará sempre disponível na plataforma.<br /><br />

    <em>Última atualização: julho de 2025</em>
  </p>
);

function Footer() {
  const currentYear = new Date().getFullYear();
  const [modalOpen, setModalOpen] = useState(null); // null | 'termos' | 'privacidade'

  return (
    <footer className="footer">
      <p>&copy; {currentYear} Rede dos Sonhos. Todos os direitos reservados.</p>
      <div className="footer-links" style={{ marginTop: 10 }}>
        <button 
          style={{ background: 'none', border: 'none', color: 'blue', cursor: 'pointer', textDecoration: 'underline', marginRight: 8 }}
          onClick={() => setModalOpen('politica')}
        >
          Política de Privacidade
        </button>
        <span style={{ margin: '0 8px' }}>|</span>
        <button 
          style={{ background: 'none', border: 'none', color: 'blue', cursor: 'pointer', textDecoration: 'underline' }}
          onClick={() => setModalOpen('termos')}
        >
          Termos de Uso
        </button>
      </div>

      {modalOpen === 'termos' && (
        <Modal 
          title="Termos de Uso"
          content={textoTermosUso}
          onClose={() => setModalOpen(null)}
        />
      )}

      {modalOpen === 'politica' && (
        <Modal 
          title="Política de Privacidade"
          content={textoPoliticaPrivacidade}
          onClose={() => setModalOpen(null)}
        />
      )}
    </footer>
  );
}

export default Footer;
