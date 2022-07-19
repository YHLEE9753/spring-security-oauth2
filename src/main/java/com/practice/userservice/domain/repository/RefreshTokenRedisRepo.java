package com.practice.userservice.domain.repository;

import com.practice.userservice.domain.model.RefreshToken;
import org.springframework.data.repository.CrudRepository;

public interface RefreshTokenRedisRepo extends CrudRepository<RefreshToken, String> {

}
