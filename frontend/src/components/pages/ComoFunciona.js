import React from 'react';
import '../styles/ComoFunciona.css';

function ComoFunciona() {
  const handleVoltar = () => window.history.back();

  return (
    
      <div className="como-funciona">
        <button className="como-funciona-voltar" onClick={handleVoltar}>
        Voltar
      </button>
      
        <h1>🌟 Bem-vindo à Rede dos Sonhos</h1>

        <div className="texto-apresentacao">
          <p>
            A Rede dos Sonhos é um espaço criado para conectar pessoas que precisam de apoio com aquelas que podem e desejam ajudar.
            Aqui, cada pessoa pode compartilhar seu "sonho" — um pedido sincero de ajuda, que pode variar desde algo simples, como uma companhia
            para uma caminhada, até causas mais complexas, como apoio financeiro para um tratamento ou projeto pessoal.
          </p>

          <p>
            Nosso objetivo é oferecer visibilidade e dignidade a quem precisa, criando um ambiente alternativo às redes sociais tradicionais,
            mais humano, seguro e transparente.
          </p>

          <h2>📝 Como funciona</h2>

          <p>
            Qualquer pessoa pode compartilhar um sonho, detalhando o que precisa: ajuda financeira, companhia, orientação ou participação em algo especial.
            Os sonhos serão publicados e exibidos na plataforma, podendo ser visualizados por toda a comunidade.
          </p>

          <p>
            Quem se interessar em ajudar, poderá entrar em contato diretamente com o autor do sonho, por meio do chat da própria Rede dos Sonhos.
            Toda conversa realizada dentro da plataforma ficará registrada para fins de transparência e responsabilização.
          </p>

          <h2>⚖️ Termo de Comprometimento e Política de Uso</h2>

          <p>
            Para garantir um ambiente de respeito e confiança, todos os usuários devem aceitar e assinar um Termo de Comprometimento no momento do cadastro.
            Ao utilizar a plataforma, o usuário declara:
          </p>

          <ul>
            <li>Estar agindo de boa fé;</li>
            <li>Não utilizar a Rede dos Sonhos para fins ilícitos, enganosos ou abusivos;</li>
            <li>Estar ciente de que a plataforma não se responsabiliza pela realização dos sonhos compartilhados;</li>
            <li>Ter plena ciência de que a negociação entre ajudante e sonhador é feita diretamente entre as partes;</li>
            <li>Que qualquer informação trocada fora da plataforma, após o compartilhamento de dados pessoais, é de responsabilidade exclusiva dos envolvidos.</li>
          </ul>

          <h2>🛡️ Segurança e Responsabilização</h2>

          <p>
            A Rede dos Sonhos não garante, intermedia nem fiscaliza a execução dos pedidos ou promessas entre os usuários. O que fazemos é proporcionar
            visibilidade e espaço para conexão entre quem precisa e quem deseja ajudar.
          </p>

          <p>
            Caso o usuário deseje continuar a conversa fora do site (por WhatsApp, e-mail, redes sociais, etc.), a Rede dos Sonhos não se responsabiliza
            por nenhum conteúdo, ação ou consequência derivada dessas interações externas.
          </p>

          <h2>❤️ Uma rede de empatia, esperança e possibilidades</h2>

          <p>
            Acreditamos que todos temos sonhos, e que muitas vezes só falta alguém disposto a ouvir — ou estender a mão. A Rede dos Sonhos existe para isso:
            criar pontes reais entre desejos e solidariedade.
          </p>

          <p>
            Junte-se a essa rede. Compartilhe um sonho. Ou ajude a realizá-lo. Cada gesto conta. Cada conexão importa.
          </p>

          <p><strong>
            Atente-se às políticas! Consulte as políticas para sua segurança e melhor compreensão.
            Dedique um tempo para ler nossas políticas e entender melhor nossos termos. </strong>
          </p>
          
        </div>
      </div>
    
  );
}

export default ComoFunciona;
