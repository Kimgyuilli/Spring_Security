package com.example.springJWT.service;

import com.example.springJWT.Entity.UserEntity;
import com.example.springJWT.dto.JoinDTO;
import com.example.springJWT.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class JoinService {
    // 회원가입 로직을 구현하는 서비스 클래스입니다.
    // 예를 들어, UserRepository를 사용하여 데이터베이스에 사용자 정보를 저장하는 등의 작업을 수행할 수 있습니다.

     UserRepository userRepository;

     private final BCryptPasswordEncoder bCryptPasswordEncoder;

        public JoinService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
            this.userRepository = userRepository;
            this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        }

     public void joinProcess(JoinDTO joinDTO){
         String username = joinDTO.getUsername();
         String password = joinDTO.getPassword();

         Boolean isExist = userRepository.existsByUsername(username);

            if (isExist) {
                throw new RuntimeException("이미 존재하는 사용자입니다.");
            }

            UserEntity data = new UserEntity();

            data.setUsername(username);
            data.setPassword(bCryptPasswordEncoder.encode(password));
            data.setRole("ROLE_ADMIN");

            userRepository.save(data);
     }

}
