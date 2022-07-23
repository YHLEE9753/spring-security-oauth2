package com.practice.userservice.domain.cache.repository;

import com.practice.userservice.domain.cache.model.BlackListToken;
import org.springframework.data.repository.CrudRepository;

public interface BlackListTokenRedisRepo  extends CrudRepository<BlackListToken, String> {

}