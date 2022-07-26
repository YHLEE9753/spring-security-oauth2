package com.practice.userservice.global.cache.repository;

import com.practice.userservice.global.cache.model.BlackListToken;
import org.springframework.data.repository.CrudRepository;

public interface BlackListTokenRedisRepo extends CrudRepository<BlackListToken, String> {

}