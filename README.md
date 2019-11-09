# Implementação de um protocolo seguro de comunicação entre client e servidor

## Cifras simétricas suportadas:
* AES
* 3DES

## Modos de Cifra suportados:
* CBC
* GCM

## Algoritmos de Síntese suportados:
* SHA-256
* SHA-512

## Processo

Consideremos que o cliente é a Alice, o server o Bob e pode existir uma Eve. A Alice e o Bob concordam num numero primo e num gerador, digamos, 3 mod 17. Cada um deles escolhe uma chave privada. Cada um deles calcula um valor usando a sua chave privada e este 3 mod 17. A Alice usa o valor do Bob para calcular o segredo partilhado e o Bob faz o mesmo. Assim conseguimos criar um valor a que apenas a Alice e o Bob têm acesso, proibindo qualquer interferência de possíveis Eves. Posteriormente, agora que temos este valor, podemos usá-lo como palavra-chave (ou até mesmo como key) para decidir uma key simétrica que será usada nos algoritmos de encriptação de texto.