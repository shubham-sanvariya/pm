package com.pm.billing_service.grpc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import billing.BillingRequest;
import billing.BillingResponse;
import billing.BillingServiceGrpc.BillingServiceImplBase;
import io.grpc.stub.StreamObserver;
import net.devh.boot.grpc.server.service.GrpcService;

@GrpcService
public class BillingGrpcService extends BillingServiceImplBase{

    private static final Logger log = LoggerFactory.getLogger(BillingGrpcService.class);

    @Override
    public void createBillingAccount(BillingRequest request, StreamObserver<BillingResponse> responseObserver) {
        log.info("createBillingAccount request received {}", request.toString());

        // Business logic e.g. save to database

        BillingResponse response = BillingResponse.newBuilder()
            .setAccountId("12345")
            .setStatus("ACTIVE")
            .build();

        responseObserver.onNext(response);
        responseObserver.onCompleted();
    }
    
}
